/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * $DragonFly: src/sys/vfs/hammer/hammer_freemap.c,v 1.4 2008/03/19 20:18:17 dillon Exp $
 */

/*
 * HAMMER freemap - bigblock allocator.  The freemap is a 2-layer blockmap
 * with one layer2 entry for each big-block in the filesystem.  Big blocks
 * are 8MB blocks.
 *
 * Our allocator is fairly straightforward, we just iterate through available
 * blocks looking for a free one.  We shortcut the iteration based on
 * layer1 availability.
 */

#include "hammer.h"

hammer_off_t
hammer_freemap_alloc(hammer_transaction_t trans, hammer_off_t owner,
		     int *errorp)
{
	hammer_volume_ondisk_t ondisk;
	hammer_off_t layer1_offset;
	hammer_off_t layer2_offset;
	hammer_off_t result_offset;
	hammer_blockmap_t blockmap;
	hammer_buffer_t buffer1 = NULL;
	hammer_buffer_t buffer2 = NULL;
	struct hammer_blockmap_layer1 *layer1;
	struct hammer_blockmap_layer2 *layer2;
	int vol_no;
	int loops = 0;

	*errorp = 0;
	ondisk = trans->rootvol->ondisk;

	blockmap = &ondisk->vol0_blockmap[HAMMER_ZONE_FREEMAP_INDEX];
	result_offset = blockmap->next_offset;
	vol_no = HAMMER_VOL_DECODE(result_offset);
	for (;;) { 
		layer1_offset = blockmap->phys_offset +
				HAMMER_BLOCKMAP_LAYER1_OFFSET(result_offset);

		layer1 = hammer_bread(trans->hmp, layer1_offset, errorp, &buffer1);
		if (layer1->phys_offset == HAMMER_BLOCKMAP_UNAVAIL) {
			/*
			 * End-of-volume, try next volume.
			 */
new_volume:
			++vol_no;
			if (vol_no >= trans->hmp->nvolumes)
				vol_no = 0;
			result_offset = HAMMER_ENCODE_RAW_BUFFER(vol_no, 0);
			if (vol_no == 0 && ++loops == 2) {
				*errorp = ENOSPC;
				result_offset = 0;
				goto done;
			}
		} else {
			layer2_offset = layer1->phys_offset +
				HAMMER_BLOCKMAP_LAYER2_OFFSET(result_offset);
			layer2 = hammer_bread(trans->hmp, layer2_offset, errorp,
					      &buffer2);
			if (layer2->u.owner == HAMMER_BLOCKMAP_FREE) {
				hammer_modify_buffer(trans, buffer2,
						     layer2, sizeof(*layer2));
				layer2->u.owner = owner &
						~HAMMER_LARGEBLOCK_MASK64;
				hammer_modify_buffer(trans, buffer1,
						     layer1, sizeof(*layer1));
				--layer1->blocks_free;
				hammer_modify_volume(trans, trans->rootvol,
				     &ondisk->vol0_stat_freebigblocks,
				     sizeof(ondisk->vol0_stat_freebigblocks));
				--ondisk->vol0_stat_freebigblocks;
				break;
			}
			if (layer1->blocks_free == 0 ||
			    layer2->u.owner == HAMMER_BLOCKMAP_UNAVAIL) {
				/*
				 * layer2 has no free blocks remaining,
				 * skip to the next layer.
				 */
				result_offset = (result_offset + HAMMER_BLOCKMAP_LAYER2_MASK) & ~HAMMER_BLOCKMAP_LAYER2_MASK;
				if (HAMMER_VOL_DECODE(result_offset) != vol_no)
					goto new_volume;
			} else {
				result_offset += HAMMER_LARGEBLOCK_SIZE;
				if (HAMMER_VOL_DECODE(result_offset) != vol_no)
					goto new_volume;
			}
		}
	}
	kprintf("hammer_freemap_alloc %016llx\n", result_offset);
	hammer_modify_volume(trans, trans->rootvol,
			     blockmap, sizeof(*blockmap));
	blockmap->next_offset = result_offset + HAMMER_LARGEBLOCK_SIZE;
done:
	if (buffer1)
		hammer_rel_buffer(buffer1, 0);
	if (buffer2)
		hammer_rel_buffer(buffer2, 0);
	return(result_offset);
}

void
hammer_freemap_free(hammer_transaction_t trans, hammer_off_t phys_offset, 
		    hammer_off_t owner, int *errorp)
{
	hammer_volume_ondisk_t ondisk;
	hammer_off_t layer1_offset;
	hammer_off_t layer2_offset;
	hammer_blockmap_t blockmap;
	hammer_buffer_t buffer1 = NULL;
	hammer_buffer_t buffer2 = NULL;
	struct hammer_blockmap_layer1 *layer1;
	struct hammer_blockmap_layer2 *layer2;

	KKASSERT((phys_offset & HAMMER_LARGEBLOCK_MASK64) == 0);

	kprintf("hammer_freemap_free %016llx\n", phys_offset);

	*errorp = 0;
	ondisk = trans->rootvol->ondisk;

	blockmap = &ondisk->vol0_blockmap[HAMMER_ZONE_FREEMAP_INDEX];
	layer1_offset = blockmap->phys_offset +
			HAMMER_BLOCKMAP_LAYER1_OFFSET(phys_offset);
	layer1 = hammer_bread(trans->hmp, layer1_offset, errorp, &buffer1);

	KKASSERT(layer1->phys_offset != HAMMER_BLOCKMAP_UNAVAIL);

	layer2_offset = layer1->phys_offset +
			HAMMER_BLOCKMAP_LAYER2_OFFSET(phys_offset);
	layer2 = hammer_bread(trans->hmp, layer2_offset, errorp, &buffer2);

	KKASSERT(layer2->u.owner == (owner & ~HAMMER_LARGEBLOCK_MASK64));
	hammer_modify_buffer(trans, buffer1, layer1, sizeof(*layer1));
	++layer1->blocks_free;
	hammer_modify_buffer(trans, buffer2, layer2, sizeof(*layer2));
	layer2->u.owner = HAMMER_BLOCKMAP_FREE;

	hammer_modify_volume(trans, trans->rootvol,
			     &ondisk->vol0_stat_freebigblocks,
			     sizeof(ondisk->vol0_stat_freebigblocks));
	++ondisk->vol0_stat_freebigblocks;

	if (buffer1)
		hammer_rel_buffer(buffer1, 0);
	if (buffer2)
		hammer_rel_buffer(buffer2, 0);
}


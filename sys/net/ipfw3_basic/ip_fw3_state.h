 /*
 * Copyright (c) 2014 - 2016 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Bill Yuan <bycn82@dragonflybsd.org>
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
 */
#ifndef _IP_FW3_STATE_H
#define _IP_FW3_STATE_H

#ifdef _KERNEL


struct ipfw3_state {
	RB_ENTRY(ipfw3_state)	entries;
	uint32_t		src_addr;
	uint32_t		dst_addr;
	uint16_t		src_port;
	uint16_t		dst_port;
	struct ip_fw		*stub;
	time_t			timestamp;
};
#define LEN_FW3_STATE sizeof(struct ipfw3_state)

int 	ip_fw3_state_cmp(struct ipfw3_state *s1, struct ipfw3_state *s2);

RB_HEAD(fw3_state_tree, ipfw3_state);
RB_PROTOTYPE(fw3_state_tree, ipfw3_state, entries, ip_fw3_state_cmp);

/* place to hold the states */
struct ipfw3_state_context {
	struct fw3_state_tree	rb_tcp_in;
	struct fw3_state_tree	rb_tcp_out;
	struct fw3_state_tree	rb_udp_in;
	struct fw3_state_tree	rb_udp_out;
	struct fw3_state_tree	rb_icmp_in;
	struct fw3_state_tree	rb_icmp_out;

	int		count_tcp_in;
	int		count_tcp_out;
	int		count_udp_in;
	int		count_udp_out;
	int		count_icmp_in;
	int		count_icmp_out;
};
#define LEN_STATE_CTX sizeof(struct ipfw3_state_context)

void	ip_fw3_append_state_dispatch(netmsg_t nmsg);
void	ip_fw3_delete_state_dispatch(netmsg_t nmsg);
int	ip_fw3_ctl_add_state(struct sockopt *sopt);
int	ip_fw3_ctl_delete_state(struct sockopt *sopt);
int	ip_fw3_ctl_flush_state(struct sockopt *sopt);
int	ip_fw3_ctl_get_state(struct sockopt *sopt);

int	ip_fw3_ctl_state_sockopt(struct sockopt *sopt);
#endif	/* _KERNEL */
#endif

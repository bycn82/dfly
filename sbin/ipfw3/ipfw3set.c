/*
 * Copyright (c) 2016 The DragonFly Project.  All rights reserved.
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

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <sysexits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <timeconv.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/ethernet.h>

#include <net/ipfw3/ip_fw3.h>
#include <net/ipfw3/ip_fw3_table.h>
#include <net/ipfw3/ip_fw3_sync.h>
#include <net/dummynet3/ip_dummynet3.h>
#include <net/ipfw3_basic/ip_fw3_basic.h>
#include <net/ipfw3_nat/ip_fw3_nat.h>

#include "ipfw3.h"
#include "ipfw3set.h"

void
set_toggle(int ac, char **av)
{

}

void
set_show(int ac, char **av)
{
	u_int32_t set_disable;
	int i, nbytes;

	void *data = NULL;
	char *msg;
	int nalloc=1000;
	nbytes = nalloc;

	while (nbytes >= nalloc) {
		nalloc = nalloc * 2+321;
		nbytes = nalloc;
		if (data == NULL) {
			if ((data = malloc(nbytes)) == NULL) {
				err(EX_OSERR, "malloc");
			}
		} else if ((data = realloc(data, nbytes)) == NULL) {
			err(EX_OSERR, "realloc");
		}
		if (do_get_x(IP_FW_GET, data, &nbytes) < 0) {
			err(EX_OSERR, "getsockopt(IP_FW_GET)");
		}
	}
	set_disable = ((struct ipfw_ioc_rule *)data)->set_disable;
	for (i = 0, msg = "disable" ; i < 31; i++)
		if ( (set_disable & (1<<i))) {
			printf("%s %d", msg, i);
			msg = "";
		}
	msg = (set_disable) ? " enable" : "enable";
	for (i = 0; i < 31; i++)
		if ( !(set_disable & (1<<i))) {
			printf("%s %d", msg, i);
			msg = "";
		}
	printf("\n");
}

void
set_swap(int ac, char **av)
{
	u_int32_t masks[2];
	u_int16_t rulenum;
	u_int8_t new_set;
	int i;

	NEXT_ARG;
	if (ac != 2)
		errx(EX_USAGE, "set swap needs 2 set numbers\n");
	rulenum = atoi(av[0]);
	new_set = atoi(av[1]);
	if (!isdigit(*(av[0])) || rulenum > 30)
		errx(EX_DATAERR, "invalid set number %s\n", av[0]);
	if (!isdigit(*(av[1])) || new_set > 30)
		errx(EX_DATAERR, "invalid set number %s\n", av[1]);
	masks[0] = (4 << 24) | (new_set << 16) | (rulenum);
	i = do_set_x(IP_FW_DEL, masks, sizeof(u_int32_t));
}

void
set_move_rule(int ac, char **av)
{

}

void
set_move_set(int ac, char **av)
{

}

/*
 * This one handles all set-related commands
 * 	ipfw set { show | enable | disable }
 * 	ipfw set swap X Y
 * 	ipfw set move X to Y
 * 	ipfw set move rule X to Y
 */
void
set_main(int ac, char **av)
{
	u_int32_t masks[2];
	u_int16_t rulenum;
	u_int8_t cmd, new_set;
	int i;

	NEXT_ARG;
	if (!ac)
		errx(EX_USAGE, "set needs command");
	if (!strncmp(*av, "show", strlen(*av)) ) {
		set_show(ac, av);
	} else if (!strncmp(*av, "swap", strlen(*av))) {
		set_swap(ac, av);
	} else if (!strncmp(*av, "move", strlen(*av))) {
		NEXT_ARG;
		if (ac && !strncmp(*av, "rule", strlen(*av))) {
			cmd = 2;
			NEXT_ARG;
		} else
			cmd = 3;
		if (ac != 3 || strncmp(av[1], "to", strlen(*av)))
			errx(EX_USAGE, "syntax: set move [rule] X to Y\n");
		rulenum = atoi(av[0]);
		new_set = atoi(av[2]);
		if (!isdigit(*(av[0])) || (cmd == 3 && rulenum > 30) ||
				(cmd == 2 && rulenum == 65535) )
			errx(EX_DATAERR, "invalid source number %s\n", av[0]);
		if (!isdigit(*(av[2])) || new_set > 30)
			errx(EX_DATAERR, "invalid dest. set %s\n", av[1]);
		masks[0] = (cmd << 24) | (new_set << 16) | (rulenum);
		i = do_set_x(IP_FW_DEL, masks, sizeof(u_int32_t));
	} else if (!strncmp(*av, "toggle", strlen(*av))) {
		set_toggle(ac, av);
	} else {
		errx(EX_USAGE, "invalid set command %s\n", *av);
	}
}


/*
 * Copyright (c) 2014 - 2018 The DragonFly Project.  All rights reserved.
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
#include <net/ipfw3_basic/ip_fw3_basic.h>
#include <net/ipfw3_basic/ip_fw3_table.h>
#include <net/ipfw3_basic/ip_fw3_state.h>
#include <net/ipfw3_basic/ip_fw3_sync.h>
#include <net/ipfw3_nat/ip_fw3_nat.h>
#include <net/dummynet3/ip_dummynet3.h>

#include "ipfw3.h"
#include "ipfw3basic.h"

extern int verbose;
extern int do_time;
extern int do_quiet;
extern int do_force;
extern int do_dynamic;
extern int do_acct;


void
state_add(int ac, char *av[])
{
	/* TODO */
}

void
state_delete(int ac, char *av[])
{
	int rulenum;
	NEXT_ARG;
	if (ac == 1 && isdigit(**av))
		rulenum = atoi(*av);
	if (do_set_x(IP_FW_STATE_DEL, &rulenum, sizeof(int)) < 0 )
		err(EX_UNAVAILABLE, "do_set_x(IP_FW_STATE_DEL)");
	if (!do_quiet)
		printf("Flushed all states.\n");
}

void
state_flush(int ac, char *av[])
{
	if (!do_force) {
		int c;

		printf("Are you sure? [yn] ");
		fflush(stdout);
		do {
			c = toupper(getc(stdin));
			while (c != '\n' && getc(stdin) != '\n')
				if (feof(stdin))
					return; /* and do not flush */
		} while (c != 'Y' && c != 'N');
		if (c == 'N')	/* user said no */
			return;
	}
	if (do_set_x(IP_FW_STATE_FLUSH, NULL, 0) < 0 )
		err(EX_UNAVAILABLE, "do_set_x(IP_FW_STATE_FLUSH)");
	if (!do_quiet)
		printf("Flushed all states.\n");
}


void
state_show(struct ipfw3_ioc_state *d, int pcwidth, int bcwidth)
{
	/* TODO */
}

void
state_list(int ac, char *av[])
{
	struct ipfw3_ioc_state *dynrules, *d;
	struct ipfw_ioc_rule *r;

	u_long rnum;
	void *data = NULL;
	int bcwidth, n, nbytes, nstat, ndyn, pcwidth;
	int exitval = EX_OK, lac;
	char **lav, *endptr;
	int seen = 0;
	int nalloc = 1024;

	NEXT_ARG;

	/* get rules or pipes from kernel, resizing array as necessary */
	nbytes = nalloc;

	while (nbytes >= nalloc) {
		nalloc = nalloc * 2 ;
		nbytes = nalloc;
		if ((data = realloc(data, nbytes)) == NULL)
			err(EX_OSERR, "realloc");
		if (do_get_x(IP_FW_GET, data, &nbytes) < 0)
			err(EX_OSERR, "do_get_x(IP_FW_GET)");
	}

	/*
	 * Count static rules.
	 */
	r = data;
	nstat = r->static_count;

	/*
	 * Count dynamic rules. This is easier as they have
	 * fixed size.
	 */
	dynrules = (struct ipfw3_ioc_state *)((void *)r + r->static_len);
	ndyn = (nbytes - r->static_len) / sizeof(*dynrules);

	/* if showing stats, figure out column widths ahead of time */
	bcwidth = pcwidth = 0;


	/* if no rule numbers were specified, list all rules */
	if (ac == 0) {
		if (do_dynamic && ndyn) {
			if (do_dynamic != 2) {
				printf("## States (%d):\n", ndyn);
			}
			for (n = 0, d = dynrules; n < ndyn; n++, d++)
				state_show(d, pcwidth, bcwidth);
		}
		goto done;
	}

	/* display specific rules requested on command line */

	if (do_dynamic != 2) {
		for (lac = ac, lav = av; lac != 0; lac--) {
			/* convert command line rule # */
			rnum = strtoul(*lav++, &endptr, 10);
			if (*endptr) {
				exitval = EX_USAGE;
				warnx("invalid rule number: %s", *(lav - 1));
				continue;
			}
			for (n = seen = 0, r = data; n < nstat;
				n++, r = (void *)r + IOC_RULESIZE(r) ) {
				if (r->rulenum > rnum)
					break;
			}
			if (!seen) {
				/* give precedence to other error(s) */
				if (exitval == EX_OK)
					exitval = EX_UNAVAILABLE;
				warnx("rule %lu does not exist", rnum);
			}
		}
	}

	ac = 0;

done:
	free(data);

	if (exitval != EX_OK)
		exit(exitval);
}

void
state_main(int ac, char **av)
{
	if (!strncmp(*av, "add", strlen(*av))) {
		state_add(ac, av);
	} else if (!strncmp(*av, "delete", strlen(*av))) {
		state_delete(ac, av);
	} else if (!strncmp(*av, "flush", strlen(*av))) {
		state_flush(ac, av);
	} else if (!strncmp(*av, "list", strlen(*av))) {
		do_dynamic = 2;
		state_list(ac, av);
	} else if (!strncmp(*av, "show", strlen(*av))) {
		do_acct = 1;
		do_dynamic =2;
		state_list(ac, av);
	} else {
		errx(EX_USAGE, "bad ipfw state command `%s'", *av);
	}
}



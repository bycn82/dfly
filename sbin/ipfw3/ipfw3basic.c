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
#include <net/ipfw3/ip_fw3_table.h>
#include <net/ipfw3/ip_fw3_sync.h>
#include <net/dummynet3/ip_dummynet3.h>
#include <net/ipfw3_basic/ip_fw3_basic.h>
#include <net/ipfw3_nat/ip_fw3_nat.h>

#include "ipfw3.h"
#include "ipfw3basic.h"


void
parse_accept(ipfw_insn **cmd, int *ac, char **av[])
{
	(*cmd)->opcode = O_BASIC_ACCEPT;
	(*cmd)->module = MODULE_BASIC_ID;
	(*cmd)->len = (*cmd)->len|LEN_OF_IPFWINSN;
	NEXT_ARG1;
	if (!strncmp(**av, "log", strlen(**av))) {
		(*cmd)->arg3 = 1;
		NEXT_ARG1;
		if (isdigit(***av)) {
			(*cmd)->arg1 = strtoul(**av, NULL, 10);
			NEXT_ARG1;
		}
	}
}

void
parse_deny(ipfw_insn **cmd, int *ac, char **av[])
{
	(*cmd)->opcode = O_BASIC_DENY;
	(*cmd)->module = MODULE_BASIC_ID;
	(*cmd)->len = (*cmd)->len|LEN_OF_IPFWINSN;
	NEXT_ARG1;
	if (!strncmp(**av, "log", strlen(**av))) {
		(*cmd)->arg3 = 1;
		NEXT_ARG1;
		if (isdigit(***av)) {
			(*cmd)->arg1 = strtoul(**av, NULL, 10);
			NEXT_ARG1;
		}
	}
}

void
show_accept(ipfw_insn *cmd, int show_or)
{
	printf(" allow");
	if (cmd->arg3) {
		printf(" log %d", cmd->arg1);
	}
}

void
show_deny(ipfw_insn *cmd, int show_or)
{
	printf(" deny");
	if (cmd->arg3) {
		printf(" log %d", cmd->arg1);
	}
}

void
prepare_default_funcs(void)
{
	/* register allow */
	register_ipfw_keyword(MODULE_BASIC_ID, O_BASIC_ACCEPT, "allow", ACTION);
	register_ipfw_keyword(MODULE_BASIC_ID, O_BASIC_ACCEPT, "accept", ACTION);
	register_ipfw_func(MODULE_BASIC_ID, O_BASIC_ACCEPT,
			(parser_func)parse_accept, (shower_func)show_accept);
	/* register deny */
	register_ipfw_keyword(MODULE_BASIC_ID, O_BASIC_DENY, "deny", ACTION);
	register_ipfw_keyword(MODULE_BASIC_ID, O_BASIC_DENY, "reject", ACTION);
	register_ipfw_func(MODULE_BASIC_ID, O_BASIC_DENY,
			(parser_func)parse_deny, (shower_func)show_deny);
}


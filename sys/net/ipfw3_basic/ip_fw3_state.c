/*
 * Copyright (c) 2014 - 2017 The DragonFly Project.  All rights reserved.
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
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systimer.h>
#include <sys/thread2.h>
#include <sys/in_cksum.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/ucred.h>
#include <sys/lock.h>
#include <sys/mplock2.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <net/netmsg2.h>
#include <net/netisr2.h>
#include <net/route.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_divert.h>
#include <netinet/if_ether.h>

#include <net/ipfw3/ip_fw.h>
#include <net/ipfw3_basic/ip_fw3_table.h>
#include <net/ipfw3_basic/ip_fw3_sync.h>
#include <net/ipfw3_basic/ip_fw3_state.h>

extern struct ipfw3_context		*fw3_ctx[MAXCPU];
extern struct ipfw3_state_context 	*fw3_state_ctx[MAXCPU];

extern int 				sysctl_var_icmp_timeout;
extern int 				sysctl_var_tcp_timeout;
extern int 				sysctl_var_udp_timeout;

MALLOC_DEFINE(M_IPFW3_STATE, "M_IPFW3_STATE", "mem for ipfw3 states");

RB_GENERATE(fw3_state_tree, ipfw3_state, entries, ip_fw3_state_cmp);

int
ip_fw3_state_cmp(struct ipfw3_state *s1, struct ipfw3_state *s2)
{
	if (s1->src_addr > s2->src_addr)
		return 1;
	if (s1->src_addr < s2->src_addr)
		return -1;

	if (s1->dst_addr > s2->dst_addr)
		return 1;
	if (s1->dst_addr < s2->dst_addr)
		return -1;

	if (s1->src_port > s2->src_port)
		return 1;
	if (s1->src_port < s2->src_port)
		return -1;

	if (s1->dst_port > s2->dst_port)
		return 1;
	if (s1->dst_port < s2->dst_port)
		return -1;

	return 0;
}

void
ip_fw3_append_state_dispatch(netmsg_t nmsg)
{
	netisr_forwardmsg_all(&nmsg->base, mycpuid + 1);
}

void
ip_fw3_delete_state_dispatch(netmsg_t nmsg)
{
	netisr_forwardmsg_all(&nmsg->base, mycpuid + 1);
}

int
ip_fw3_ctl_add_state(struct sockopt *sopt)
{
	return 0;
}

int
ip_fw3_ctl_delete_state(struct sockopt *sopt)
{
	return 0;
}

int
ip_fw3_ctl_flush_state(struct sockopt *sopt)
{

	return 0;
}

int
ip_fw3_ctl_get_state(struct sockopt *sopt)
{
	struct ipfw3_state_context *state_ctx;
	struct ipfw3_state *s;

	size_t sopt_size, total_len = 0;
	struct ipfw_ioc_state *ioc;

	sopt_size = sopt->sopt_valsize;
	ioc = (struct ipfw_ioc_state *)sopt->sopt_val;
	/* icmp states only in CPU 0 */
	int cpu = 0;

	/* udp states */
	for (cpu = 0; cpu < ncpus; cpu++) {
		state_ctx = fw3_state_ctx[cpu];
		RB_FOREACH(s, fw3_state_tree, &state_ctx->rb_udp_out) {
				total_len += LEN_IOC_FW3_STATE;
				if (total_len > sopt_size)
					goto nospace;
				ioc->src_addr.s_addr = ntohl(s->src_addr);
				ioc->dst_addr.s_addr = s->dst_addr;
				ioc->src_port = s->src_port;
				ioc->dst_port = s->dst_port;
				ioc->cpu_id = cpu;
				ioc->proto = IPPROTO_UDP;
				ioc->life = s->timestamp +
					sysctl_var_udp_timeout - time_uptime;
				ioc++;
		}
	}

	sopt->sopt_valsize = total_len;
	return 0;
nospace:
	return 0;
}



int
ip_fw3_ctl_state_sockopt(struct sockopt *sopt)
{
	int error = 0;
	switch (sopt->sopt_name) {
		case IP_FW_STATE_ADD:
			error = ip_fw3_ctl_add_state(sopt);
			break;
		case IP_FW_STATE_DEL:
			error = ip_fw3_ctl_delete_state(sopt);
			break;
		case IP_FW_STATE_FLUSH:
			error = ip_fw3_ctl_flush_state(sopt);
			break;
		case IP_FW_STATE_GET:
			error = ip_fw3_ctl_get_state(sopt);
			break;
	}
	return error;
}


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
#include <sys/tree.h>

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
#include <net/ipfw3_basic/ip_fw3_basic.h>
#include <net/ipfw3_basic/ip_fw3_state.h>

MALLOC_DEFINE(M_IP_FW3_BASIC, "IPFW3_BASIC", "ipfw3_basic module");

struct ipfw3_state_context 		*fw3_state_ctx[MAXCPU];

extern struct ipfw3_context		*fw3_ctx[MAXCPU];
extern struct ipfw3_sync_context 	fw3_sync_ctx;
extern int 				sysctl_var_fw3_verbose;
extern ipfw_basic_delete_state_t 	*ipfw_basic_flush_state_prt;
extern ipfw_basic_append_state_t 	*ipfw_basic_append_state_prt;
extern ipfw_sync_send_state_t 		*ipfw_sync_send_state_prt;
extern ipfw_sync_install_state_t 	*ipfw_sync_install_state_prt;

static struct callout 		ip_fw3_basic_cleanup_callout;
static int 			sysctl_var_cleanup_interval = 1;

static int 			sysctl_var_state_max_tcp_in = 4096;
static int 			sysctl_var_state_max_udp_in = 4096;
static int 			sysctl_var_state_max_icmp_in = 10;

static int 			sysctl_var_state_max_tcp_out = 4096;
static int 			sysctl_var_state_max_udp_out = 4096;
static int 			sysctl_var_state_max_icmp_out = 10;

static int 			sysctl_var_icmp_timeout = 10;
static int 			sysctl_var_tcp_timeout = 60;
static int 			sysctl_var_udp_timeout = 30;

void	ipfw_sync_install_state(struct cmd_send_state *cmd);

SYSCTL_NODE(_net_inet_ip, OID_AUTO, fw3_basic, CTLFLAG_RW, 0, "Firewall Basic");

SYSCTL_INT(_net_inet_ip_fw3_basic, OID_AUTO, state_max_tcp_in, CTLFLAG_RW,
		&sysctl_var_state_max_tcp_in, 0, "maximum of tcp state in");
SYSCTL_INT(_net_inet_ip_fw3_basic, OID_AUTO, state_max_tcp_out, CTLFLAG_RW,
		&sysctl_var_state_max_tcp_out, 0, "maximum of tcp state out");
SYSCTL_INT(_net_inet_ip_fw3_basic, OID_AUTO, state_max_udp_in, CTLFLAG_RW,
		&sysctl_var_state_max_udp_in, 0, "maximum of udp state in");
SYSCTL_INT(_net_inet_ip_fw3_basic, OID_AUTO, state_max_udp_out, CTLFLAG_RW,
		&sysctl_var_state_max_udp_out, 0, "maximum of udp state out");
SYSCTL_INT(_net_inet_ip_fw3_basic, OID_AUTO, state_max_icmp_in, CTLFLAG_RW,
		&sysctl_var_state_max_icmp_in, 0, "maximum of icmp state in");
SYSCTL_INT(_net_inet_ip_fw3_basic, OID_AUTO, state_max_icmp_out, CTLFLAG_RW,
		&sysctl_var_state_max_icmp_out, 0, "maximum of icmp state out");

SYSCTL_INT(_net_inet_ip_fw3_basic, OID_AUTO, cleanup_interval, CTLFLAG_RW,
		&sysctl_var_cleanup_interval, 0,
		"default state expiry check interval");
SYSCTL_INT(_net_inet_ip_fw3_basic, OID_AUTO, icmp_timeout, CTLFLAG_RW,
		&sysctl_var_icmp_timeout, 0, "default icmp state life time");
SYSCTL_INT(_net_inet_ip_fw3_basic, OID_AUTO, tcp_timeout, CTLFLAG_RW,
		&sysctl_var_tcp_timeout, 0, "default tcp state life time");
SYSCTL_INT(_net_inet_ip_fw3_basic, OID_AUTO, udp_timeout, CTLFLAG_RW,
		&sysctl_var_udp_timeout, 0, "default udp state life time");


static struct ip_fw *lookup_next_rule(struct ip_fw *me);
static int iface_match(struct ifnet *ifp, ipfw_insn_if *cmd);

static struct ip_fw *
lookup_next_rule(struct ip_fw *me)
{
	struct ip_fw *rule = NULL;
	ipfw_insn *cmd;

	/* look for action, in case it is a skipto */
	cmd = ACTION_PTR(me);
	if ((int)cmd->module == MODULE_BASIC_ID &&
		(int)cmd->opcode == O_BASIC_SKIPTO) {
		for (rule = me->next; rule; rule = rule->next) {
			if (rule->rulenum >= cmd->arg1)
				break;
		}
	}
	if (rule == NULL) /* failure or not a skipto */
		rule = me->next;

	me->next_rule = rule;
	return rule;
}

void
ipfw_sync_install_state(struct cmd_send_state *cmd)
{
	/* TODO */
}

static int
iface_match(struct ifnet *ifp, ipfw_insn_if *cmd)
{
	if (ifp == NULL)	/* no iface with this packet, match fails */
		return 0;

	/* Check by name or by IP address */
	if (cmd->name[0] != '\0') { /* match by name */
		/* Check name */
		if (cmd->p.glob) {
			if (kfnmatch(cmd->name, ifp->if_xname, 0) == 0)
				return(1);
		} else {
			if (strncmp(ifp->if_xname, cmd->name, IFNAMSIZ) == 0)
				return(1);
		}
	} else {
		struct ifaddr_container *ifac;

		TAILQ_FOREACH(ifac, &ifp->if_addrheads[mycpuid], ifa_link) {
			struct ifaddr *ia = ifac->ifa;

			if (ia->ifa_addr == NULL)
				continue;
			if (ia->ifa_addr->sa_family != AF_INET)
				continue;
			if (cmd->p.ip.s_addr ==
				((struct sockaddr_in *)
				(ia->ifa_addr))->sin_addr.s_addr)
					return(1);	/* match */

		}
	}
	return 0;	/* no match, fail ... */
}

/* implimentation of the checker functions */
void
check_count(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	(*f)->pcnt++;
	(*f)->bcnt += ip_len;
	(*f)->timestamp = time_second;
	*cmd_ctl = IP_FW_CTL_NEXT;
}

void
check_skipto(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	(*f)->pcnt++;
	(*f)->bcnt += ip_len;
	(*f)->timestamp = time_second;
	if ((*f)->next_rule == NULL)
		lookup_next_rule(*f);
	*f = (*f)->next_rule;
	*cmd_ctl = IP_FW_CTL_AGAIN;
}

void
check_forward(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	struct sockaddr_in *sin, *sa;
	struct m_tag *mtag;

	if ((*args)->eh) {	/* not valid on layer2 pkts */
		*cmd_ctl=IP_FW_CTL_NEXT;
		return;
	}

	(*f)->pcnt++;
	(*f)->bcnt += ip_len;
	(*f)->timestamp = time_second;
	if ((*f)->next_rule == NULL)
		lookup_next_rule(*f);

	mtag = m_tag_get(PACKET_TAG_IPFORWARD,
			sizeof(*sin), M_INTWAIT | M_NULLOK);
	if (mtag == NULL) {
		*cmd_val = IP_FW_DENY;
		*cmd_ctl = IP_FW_CTL_DONE;
		return;
	}
	sin = m_tag_data(mtag);
	sa = &((ipfw_insn_sa *)cmd)->sa;
	/* arg3: count of the dest, arg1: type of fwd */
	int i = 0;
	if(cmd->arg3 > 1) {
		if (cmd->arg1 == 0) {		/* type: random */
			i = krandom() % cmd->arg3;
		} else if (cmd->arg1 == 1) {	/* type: round-robin */
			i = cmd->arg2++ % cmd->arg3;
		} else if (cmd->arg1 == 2) {	/* type: sticky */
			struct ip *ip = mtod((*args)->m, struct ip *);
			i = ip->ip_src.s_addr & (cmd->arg3 - 1);
		}
		sa += i;
	}
	*sin = *sa;	/* apply the destination */
	m_tag_prepend((*args)->m, mtag);
	(*args)->m->m_pkthdr.fw_flags |= IPFORWARD_MBUF_TAGGED;
	(*args)->m->m_pkthdr.fw_flags &= ~BRIDGE_MBUF_TAGGED;
	*cmd_ctl = IP_FW_CTL_DONE;
	*cmd_val = IP_FW_PASS;
}

void
check_check_state(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	/* state_tree 1 same direction, state_tree2 opposite direction */
	struct fw3_state_tree *state_tree1, *state_tree2;
	struct ip *ip = mtod((*args)->m, struct ip *);
	struct ipfw3_state_context *state_ctx = fw3_state_ctx[mycpuid];
	struct ipfw3_state *s, *k, key;

	k = &key;
	memset(k, 0, LEN_FW3_STATE);

	if ((*args)->oif == NULL) {
		switch (ip->ip_p) {
		case IPPROTO_TCP:
			state_tree1 = &state_ctx->rb_tcp_in;
			state_tree2 = &state_ctx->rb_tcp_out;
		break;
		case IPPROTO_UDP:
			state_tree1 = &state_ctx->rb_udp_in;
			state_tree2 = &state_ctx->rb_udp_out;
		break;
		case IPPROTO_ICMP:
			state_tree1 = &state_ctx->rb_icmp_in;
			state_tree2 = &state_ctx->rb_icmp_out;
		break;
		default:
			goto oops;
		}
	} else {
		switch (ip->ip_p) {
		case IPPROTO_TCP:
			state_tree1 = &state_ctx->rb_tcp_out;
			state_tree2 = &state_ctx->rb_tcp_in;
		break;
		case IPPROTO_UDP:
			state_tree1 = &state_ctx->rb_udp_out;
			state_tree2 = &state_ctx->rb_udp_in;
		break;
		case IPPROTO_ICMP:
			state_tree1 = &state_ctx->rb_icmp_out;
			state_tree2 = &state_ctx->rb_icmp_in;
		break;
		default:
			goto oops;
		}
	}

	k->src_addr = (*args)->f_id.src_ip;
	k->dst_addr = (*args)->f_id.dst_ip;
	k->src_port = (*args)->f_id.src_port;
	k->dst_port = (*args)->f_id.dst_port;
	s = RB_FIND(fw3_state_tree, state_tree1, k);
	if (s != NULL) {
		(*f)->pcnt++;
		(*f)->bcnt += ip_len;
		(*f)->timestamp = time_second;
		*f = s->stub;
		*cmd_val = IP_FW_PASS;
		*cmd_ctl = IP_FW_CTL_CHK_STATE;
		return;
	}
	k->dst_addr = (*args)->f_id.src_ip;
	k->src_addr = (*args)->f_id.dst_ip;
	k->dst_port = (*args)->f_id.src_port;
	k->src_port = (*args)->f_id.dst_port;
	s = RB_FIND(fw3_state_tree, state_tree2, k);
	if (s != NULL) {
		(*f)->pcnt++;
		(*f)->bcnt += ip_len;
		(*f)->timestamp = time_second;
		*f = s->stub;
		*cmd_val = IP_FW_PASS;
		*cmd_ctl = IP_FW_CTL_CHK_STATE;
		return;
	}
oops:
	*cmd_val = IP_FW_NOT_MATCH;
	*cmd_ctl = IP_FW_CTL_NEXT;
}

void
check_in(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	*cmd_ctl = IP_FW_CTL_NO;
	*cmd_val = ((*args)->oif == NULL);
}

void
check_out(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	*cmd_ctl = IP_FW_CTL_NO;
	*cmd_val = ((*args)->oif != NULL);
}

void
check_via(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	*cmd_ctl = IP_FW_CTL_NO;
	*cmd_val = iface_match((*args)->oif ?
			(*args)->oif : (*args)->m->m_pkthdr.rcvif,
			(ipfw_insn_if *)cmd);
}

void
check_proto(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	*cmd_ctl = IP_FW_CTL_NO;
	*cmd_val = ((*args)->f_id.proto == cmd->arg1);
}

void
check_prob(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	*cmd_ctl = IP_FW_CTL_NO;
	*cmd_val = (krandom() % 100) < cmd->arg1;
}

void
check_from(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	u_int hlen = 0;
	struct mbuf *m = (*args)->m;
	struct ip *ip = mtod(m, struct ip *);
	struct in_addr src_ip = ip->ip_src;

	if ((*args)->eh == NULL ||
		(m->m_pkthdr.len >= sizeof(struct ip) &&
		ntohs((*args)->eh->ether_type) == ETHERTYPE_IP)) {
		hlen = ip->ip_hl << 2;
	}
	*cmd_val = (hlen > 0 &&
			((ipfw_insn_ip *)cmd)->addr.s_addr == src_ip.s_addr);
	*cmd_ctl = IP_FW_CTL_NO;
}

void
check_from_lookup(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	struct ipfw3_context *ctx = fw3_ctx[mycpuid];
	struct ipfw_table_context *table_ctx;
	struct radix_node_head *rnh;
	struct sockaddr_in sa;

	struct mbuf *m = (*args)->m;
	struct ip *ip = mtod(m, struct ip *);
	struct in_addr src_ip = ip->ip_src;

	*cmd_val = IP_FW_NOT_MATCH;

	table_ctx = ctx->table_ctx;
	table_ctx += cmd->arg1;

        if (table_ctx->type != 0) {
                rnh = table_ctx->node;
                sa.sin_len = 8;
                sa.sin_addr.s_addr = src_ip.s_addr;
                if(rnh->rnh_lookup((char *)&sa, NULL, rnh) != NULL)
                        *cmd_val = IP_FW_MATCH;
        }
	*cmd_ctl = IP_FW_CTL_NO;
}

void
check_from_me(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	u_int hlen = 0;
	struct mbuf *m = (*args)->m;
	struct ip *ip = mtod(m, struct ip *);
	struct in_addr src_ip = ip->ip_src;

	if ((*args)->eh == NULL ||
		(m->m_pkthdr.len >= sizeof(struct ip) &&
		ntohs((*args)->eh->ether_type) == ETHERTYPE_IP)) {
		hlen = ip->ip_hl << 2;
	}
	*cmd_ctl = IP_FW_CTL_NO;
	if (hlen > 0) {
		struct ifnet *tif;
		tif = INADDR_TO_IFP(&src_ip);
		*cmd_val = (tif != NULL);
	} else {
		*cmd_val = IP_FW_NOT_MATCH;
	}
}

void
check_from_mask(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	u_int hlen = 0;
	struct mbuf *m = (*args)->m;
	struct ip *ip = mtod(m, struct ip *);
	struct in_addr src_ip = ip->ip_src;

	if ((*args)->eh == NULL ||
		(m->m_pkthdr.len >= sizeof(struct ip) &&
		ntohs((*args)->eh->ether_type) == ETHERTYPE_IP)) {
		hlen = ip->ip_hl << 2;
	}

	*cmd_ctl = IP_FW_CTL_NO;
	*cmd_val = (hlen > 0 &&
			((ipfw_insn_ip *)cmd)->addr.s_addr ==
			(src_ip.s_addr &
			((ipfw_insn_ip *)cmd)->mask.s_addr));
}

void
check_to(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	u_int hlen = 0;
	struct mbuf *m = (*args)->m;
	struct ip *ip = mtod(m, struct ip *);
	struct in_addr dst_ip = ip->ip_dst;

	if ((*args)->eh == NULL ||
		(m->m_pkthdr.len >= sizeof(struct ip) &&
		 ntohs((*args)->eh->ether_type) == ETHERTYPE_IP)) {
		hlen = ip->ip_hl << 2;
	}
	*cmd_val = (hlen > 0 &&
			((ipfw_insn_ip *)cmd)->addr.s_addr == dst_ip.s_addr);
	*cmd_ctl = IP_FW_CTL_NO;
}

void
check_to_lookup(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	struct ipfw3_context *ctx = fw3_ctx[mycpuid];
	struct ipfw_table_context *table_ctx;
	struct radix_node_head *rnh;
	struct sockaddr_in sa;

	struct mbuf *m = (*args)->m;
	struct ip *ip = mtod(m, struct ip *);
	struct in_addr dst_ip = ip->ip_dst;

	*cmd_val = IP_FW_NOT_MATCH;

	table_ctx = ctx->table_ctx;
	table_ctx += cmd->arg1;

        if (table_ctx->type != 0) {
                rnh = table_ctx->node;
                sa.sin_len = 8;
                sa.sin_addr.s_addr = dst_ip.s_addr;
                if(rnh->rnh_lookup((char *)&sa, NULL, rnh) != NULL)
                        *cmd_val = IP_FW_MATCH;
        }
	*cmd_ctl = IP_FW_CTL_NO;
}

void
check_to_me(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	u_int hlen = 0;
	struct mbuf *m = (*args)->m;
	struct ip *ip = mtod(m, struct ip *);
	struct in_addr dst_ip = ip->ip_dst;

	if ((*args)->eh == NULL ||
		(m->m_pkthdr.len >= sizeof(struct ip) &&
		ntohs((*args)->eh->ether_type) == ETHERTYPE_IP)) {
		hlen = ip->ip_hl << 2;
	}
	*cmd_ctl = IP_FW_CTL_NO;
	if (hlen > 0) {
		struct ifnet *tif;
		tif = INADDR_TO_IFP(&dst_ip);
		*cmd_val = (tif != NULL);
	} else {
		*cmd_val = IP_FW_NOT_MATCH;
	}
}

void
check_to_mask(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	u_int hlen = 0;
	struct mbuf *m = (*args)->m;
	struct ip *ip = mtod(m, struct ip *);
	struct in_addr dst_ip = ip->ip_dst;

	if ((*args)->eh == NULL ||
		(m->m_pkthdr.len >= sizeof(struct ip) &&
		ntohs((*args)->eh->ether_type) == ETHERTYPE_IP)) {
		hlen = ip->ip_hl << 2;
	}

	*cmd_ctl = IP_FW_CTL_NO;
	*cmd_val = (hlen > 0 &&
			((ipfw_insn_ip *)cmd)->addr.s_addr ==
			(dst_ip.s_addr &
			((ipfw_insn_ip *)cmd)->mask.s_addr));
}

void
check_keep_state(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	/* state_tree 1 same direction, state_tree2 opposite direction */
	struct fw3_state_tree *the_tree = NULL;
	struct ip *ip = mtod((*args)->m, struct ip *);
	struct ipfw3_state_context *state_ctx = fw3_state_ctx[mycpuid];
	struct ipfw3_state *s, *k, key;
	int states_matched = 0, *the_count, the_max;

	k = &key;
	memset(k, 0, LEN_FW3_STATE);
	if ((*args)->oif == NULL) {
		switch (ip->ip_p) {
		case IPPROTO_TCP:
			the_tree = &state_ctx->rb_tcp_in;
			the_count = &state_ctx->count_tcp_in;
			the_max = sysctl_var_state_max_tcp_in;
		break;
		case IPPROTO_UDP:
			the_tree = &state_ctx->rb_udp_in;
			the_count = &state_ctx->count_udp_in;
			the_max = sysctl_var_state_max_udp_in;
		break;
		case IPPROTO_ICMP:
			the_tree = &state_ctx->rb_icmp_in;
			the_count = &state_ctx->count_icmp_in;
			the_max = sysctl_var_state_max_icmp_in;
		break;
		default:
			goto done;
		}
	} else {
		switch (ip->ip_p) {
		case IPPROTO_TCP:
			the_tree = &state_ctx->rb_tcp_out;
			the_count = &state_ctx->count_tcp_out;
			the_max = sysctl_var_state_max_tcp_out;
		break;
		case IPPROTO_UDP:
			the_tree = &state_ctx->rb_udp_out;
			the_count = &state_ctx->count_udp_out;
			the_max = sysctl_var_state_max_udp_out;
		break;
		case IPPROTO_ICMP:
			the_tree = &state_ctx->rb_icmp_out;
			the_count = &state_ctx->count_icmp_out;
			the_max = sysctl_var_state_max_icmp_out;
		break;
		default:
			goto done;
		}
	}
	*cmd_ctl = IP_FW_CTL_NO;
	k->src_addr = (*args)->f_id.src_ip;
	k->dst_addr = (*args)->f_id.dst_ip;
	k->src_port = (*args)->f_id.src_port;
	k->dst_port = (*args)->f_id.dst_port;
	/* cmd->arg3 is `limit type` */
	if (cmd->arg3 == 0) {
		s = RB_FIND(fw3_state_tree, the_tree, k);
		if (s != NULL) {
			goto done;
		}
	} else {
		RB_FOREACH(s, fw3_state_tree, the_tree) {
			if (cmd->arg3 == 1 && s->src_addr == k->src_addr) {
				states_matched++;
			} else if (cmd->arg3 == 2 && s->src_port == k->src_port) {
				states_matched++;
			} else if (cmd->arg3 == 3 && s->dst_addr == k->dst_addr) {
				states_matched++;
			} else if (cmd->arg3 == 4 && s->dst_port == k->dst_port) {
				states_matched++;
			}
		}
		if (states_matched >= cmd->arg1) {
			goto done;
		}
	}
	if (*the_count <= the_max) {
		(*the_count)++;
		s = kmalloc(LEN_FW3_STATE, M_IP_FW3_BASIC,
				M_INTWAIT | M_NULLOK | M_ZERO);
		s->src_addr = k->src_addr;
		s->dst_addr = k->dst_addr;
		s->src_port = k->src_port;
		s->dst_port = k->dst_port;
		s->stub = *f;
		RB_INSERT(fw3_state_tree, the_tree, s);
	}
done:
	*cmd_ctl = IP_FW_CTL_NO;
	*cmd_val = IP_FW_MATCH;
}

void
check_tag(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	struct m_tag *mtag = m_tag_locate((*args)->m,
			MTAG_IPFW, cmd->arg1, NULL);
	if (mtag == NULL) {
		mtag = m_tag_alloc(MTAG_IPFW,cmd->arg1, 0, M_NOWAIT);
		if (mtag != NULL)
			m_tag_prepend((*args)->m, mtag);

	}
	(*f)->pcnt++;
	(*f)->bcnt += ip_len;
	(*f)->timestamp = time_second;
	*cmd_ctl = IP_FW_CTL_NEXT;
}

void
check_untag(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	struct m_tag *mtag = m_tag_locate((*args)->m,
			MTAG_IPFW, cmd->arg1, NULL);
	if (mtag != NULL)
		m_tag_delete((*args)->m, mtag);

	(*f)->pcnt++;
	(*f)->bcnt += ip_len;
	(*f)->timestamp = time_second;
	*cmd_ctl = IP_FW_CTL_NEXT;
}

void
check_tagged(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	*cmd_ctl = IP_FW_CTL_NO;
	if (m_tag_locate( (*args)->m, MTAG_IPFW,cmd->arg1, NULL) != NULL )
		*cmd_val = IP_FW_MATCH;
	else
		*cmd_val = IP_FW_NOT_MATCH;
}

void
check_src_port(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
        struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
        *cmd_ctl = IP_FW_CTL_NO;
        if ((*args)->f_id.src_port == cmd->arg1)
                *cmd_val = IP_FW_MATCH;
        else
                *cmd_val = IP_FW_NOT_MATCH;
}

void
check_dst_port(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
        struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
        *cmd_ctl = IP_FW_CTL_NO;
        if ((*args)->f_id.dst_port == cmd->arg1)
                *cmd_val = IP_FW_MATCH;
        else
                *cmd_val = IP_FW_NOT_MATCH;
}

void
check_src_n_port(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	struct in_addr src_ip;
	u_int hlen = 0;
	struct mbuf *m = (*args)->m;
	struct ip *ip = mtod(m, struct ip *);
	src_ip = ip->ip_src;
	if ((*args)->eh == NULL ||
		(m->m_pkthdr.len >= sizeof(struct ip) &&
		ntohs((*args)->eh->ether_type) == ETHERTYPE_IP)) {
		hlen = ip->ip_hl << 2;
	}
	*cmd_val = (hlen > 0 && ((ipfw_insn_ip *)cmd)->addr.s_addr == src_ip.s_addr);
	*cmd_ctl = IP_FW_CTL_NO;
	if (*cmd_val && (*args)->f_id.src_port == cmd->arg1)
		*cmd_val = IP_FW_MATCH;
	else
		*cmd_val = IP_FW_NOT_MATCH;
}

void
check_dst_n_port(int *cmd_ctl, int *cmd_val, struct ip_fw_args **args,
	struct ip_fw **f, ipfw_insn *cmd, uint16_t ip_len)
{
	struct in_addr dst_ip;
	u_int hlen = 0;
	struct mbuf *m = (*args)->m;
	struct ip *ip = mtod(m, struct ip *);
	dst_ip = ip->ip_dst;
	if ((*args)->eh == NULL ||
		(m->m_pkthdr.len >= sizeof(struct ip) &&
		 ntohs((*args)->eh->ether_type) == ETHERTYPE_IP)) {
		hlen = ip->ip_hl << 2;
	}
	*cmd_val = (hlen > 0 && ((ipfw_insn_ip *)cmd)->addr.s_addr == dst_ip.s_addr);
	*cmd_ctl = IP_FW_CTL_NO;
	if (*cmd_val && (*args)->f_id.dst_port == cmd->arg1)
		*cmd_val = IP_FW_MATCH;
	else
		*cmd_val = IP_FW_NOT_MATCH;
}



static void
ip_fw3_basic_add_state(struct ipfw_ioc_state *ioc_state)
{
	/* TODO */
}

void
ip_fw3_basic_flush_state_dispatch(netmsg_t nmsg)
{
	struct ipfw3_state_context *state_ctx = fw3_state_ctx[mycpuid];
	struct ipfw3_state *s, *tmp;

	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_icmp_in, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_icmp_in, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_icmp_out, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_icmp_out, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_tcp_in, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_tcp_in, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_tcp_out, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_tcp_out, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_udp_in, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_udp_in, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_udp_out, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_udp_out, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	netisr_forwardmsg_all(&nmsg->base, mycpuid + 1);
}

static void
ip_fw3_basic_flush_state(struct ip_fw *rule)
{
	struct netmsg_base msg;
	netmsg_init(&msg, NULL, &curthread->td_msgport, 0,
			ip_fw3_basic_flush_state_dispatch);
	netisr_domsg(&msg, 0);
}


static void
ip_fw3_basic_cleanup_func_dispatch(netmsg_t nmsg)
{
	struct ipfw3_state_context *state_ctx = fw3_state_ctx[mycpuid];
	struct ipfw3_state *s, *tmp;

	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_icmp_in, tmp) {
		if (time_uptime - s->timestamp > sysctl_var_icmp_timeout) {
			RB_REMOVE(fw3_state_tree, &state_ctx->rb_icmp_in, s);
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_icmp_out, tmp) {
		if (time_uptime - s->timestamp > sysctl_var_icmp_timeout) {
			RB_REMOVE(fw3_state_tree, &state_ctx->rb_icmp_out, s);
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_tcp_in, tmp) {
		if (time_uptime - s->timestamp > sysctl_var_tcp_timeout) {
			RB_REMOVE(fw3_state_tree, &state_ctx->rb_tcp_in, s);
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_tcp_out, tmp) {
		if (time_uptime - s->timestamp > sysctl_var_tcp_timeout) {
			RB_REMOVE(fw3_state_tree, &state_ctx->rb_tcp_out, s);
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_udp_in, tmp) {
		if (time_uptime - s->timestamp > sysctl_var_udp_timeout) {
			RB_REMOVE(fw3_state_tree, &state_ctx->rb_udp_in, s);
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_udp_out, tmp) {
		if (time_uptime - s->timestamp > sysctl_var_udp_timeout) {
			RB_REMOVE(fw3_state_tree, &state_ctx->rb_udp_out, s);
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	netisr_forwardmsg_all(&nmsg->base, mycpuid + 1);
}

static void
ip_fw3_basic_cleanup_func(void *dummy __unused)
{
	struct netmsg_base msg;
	netmsg_init(&msg, NULL, &curthread->td_msgport, 0,
			ip_fw3_basic_cleanup_func_dispatch);
	netisr_domsg(&msg, 0);

	callout_reset(&ip_fw3_basic_cleanup_callout,
			sysctl_var_cleanup_interval * hz,
			ip_fw3_basic_cleanup_func, NULL);
}

static void
ipfw_basic_init_dispatch(netmsg_t msg)
{
	struct ipfw3_state_context *tmp;

	tmp = kmalloc(LEN_STATE_CTX, M_IP_FW3_BASIC, M_WAITOK | M_ZERO);
	RB_INIT(&tmp->rb_icmp_in);
	RB_INIT(&tmp->rb_icmp_out);
	RB_INIT(&tmp->rb_tcp_in);
	RB_INIT(&tmp->rb_tcp_out);
	RB_INIT(&tmp->rb_udp_in);
	RB_INIT(&tmp->rb_udp_out);
	fw3_state_ctx[mycpuid] = tmp;
	netisr_forwardmsg_all(&msg->base, mycpuid + 1);
}

static int
ip_fw3_basic_init(void)
{
	struct netmsg_base msg;

	ipfw_basic_flush_state_prt = ip_fw3_basic_flush_state;
	ipfw_basic_append_state_prt = ip_fw3_basic_add_state;
	ipfw_sync_install_state_prt = ipfw_sync_install_state;

	ip_fw3_register_module(MODULE_BASIC_ID, MODULE_BASIC_NAME);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID, O_BASIC_COUNT,
			(filter_func)check_count);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID, O_BASIC_SKIPTO,
			(filter_func)check_skipto);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID, O_BASIC_FORWARD,
			(filter_func)check_forward);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID, O_BASIC_KEEP_STATE,
			(filter_func)check_keep_state);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID, O_BASIC_CHECK_STATE,
			(filter_func)check_check_state);

	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IN, (filter_func)check_in);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_OUT, (filter_func)check_out);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_VIA, (filter_func)check_via);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_XMIT, (filter_func)check_via);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_RECV, (filter_func)check_via);

	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_PROTO, (filter_func)check_proto);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_PROB, (filter_func)check_prob);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_SRC, (filter_func)check_from);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_SRC_LOOKUP, (filter_func)check_from_lookup);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_SRC_ME, (filter_func)check_from_me);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_SRC_MASK, (filter_func)check_from_mask);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_DST, (filter_func)check_to);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_DST_LOOKUP, (filter_func)check_to_lookup);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_DST_ME, (filter_func)check_to_me);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_DST_MASK, (filter_func)check_to_mask);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_TAG, (filter_func)check_tag);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_UNTAG, (filter_func)check_untag);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_TAGGED, (filter_func)check_tagged);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_SRCPORT, (filter_func)check_src_port);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_DSTPORT, (filter_func)check_dst_port);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_SRC_N_PORT, (filter_func)check_src_n_port);
	ip_fw3_register_filter_funcs(MODULE_BASIC_ID,
			O_BASIC_IP_DST_N_PORT, (filter_func)check_dst_n_port);

	netmsg_init(&msg, NULL, &curthread->td_msgport,
			0, ipfw_basic_init_dispatch);
	netisr_domsg(&msg, 0);


	callout_init_mp(&ip_fw3_basic_cleanup_callout);
	callout_reset(&ip_fw3_basic_cleanup_callout,
			sysctl_var_cleanup_interval * hz,
			ip_fw3_basic_cleanup_func,
			NULL);
	return 0;
}

static void
ip_fw3_basic_fini_dispatch(netmsg_t msg)
{
	struct ipfw3_state_context *state_ctx = fw3_state_ctx[mycpuid];
	struct ipfw3_state *s, *tmp;

	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_icmp_in, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_icmp_in, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_icmp_out, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_icmp_out, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_tcp_in, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_tcp_in, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_tcp_out, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_tcp_out, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_udp_in, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_udp_in, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}
	RB_FOREACH_SAFE(s, fw3_state_tree, &state_ctx->rb_udp_out, tmp) {
		RB_REMOVE(fw3_state_tree, &state_ctx->rb_udp_out, s);
		if (s != NULL) {
			kfree(s, M_IP_FW3_BASIC);
		}
	}

	kfree(fw3_state_ctx[mycpuid], M_IP_FW3_BASIC);
	netisr_forwardmsg_all(&msg->base, mycpuid + 1);
}

static int
ip_fw3_basic_fini(void)
{
	struct netmsg_base msg;

	callout_stop(&ip_fw3_basic_cleanup_callout);


	netmsg_init(&msg, NULL, &curthread->td_msgport,
		0, ip_fw3_basic_fini_dispatch);

	netisr_domsg(&msg, 0);

	return ip_fw3_unregister_module(MODULE_BASIC_ID);
}


static int
ipfw3_basic_modevent(module_t mod, int type, void *data)
{
	int err;
	switch (type) {
		case MOD_LOAD:
			err = ip_fw3_basic_init();
			break;
		case MOD_UNLOAD:
			err = ip_fw3_basic_fini();
			break;
		default:
			err = 1;
	}
	return err;
}

static moduledata_t ipfw3_basic_mod = {
	"ipfw3_basic",
	ipfw3_basic_modevent,
	NULL
};
DECLARE_MODULE(ipfw3_basic, ipfw3_basic_mod, SI_SUB_PROTO_END, SI_ORDER_ANY);
MODULE_DEPEND(ipfw3_basic, ipfw3, 1, 1, 1);
MODULE_VERSION(ipfw3_basic, 1);

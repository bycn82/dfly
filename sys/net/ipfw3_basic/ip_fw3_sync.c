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
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/socketvar2.h>
#include <sys/socketops.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/ucred.h>
#include <sys/in_cksum.h>
#include <sys/lock.h>
#include <sys/kthread.h>
#include <sys/thread2.h>
#include <sys/mplock2.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
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

#include <net/if.h>
#include <net/route.h>
#include <net/pfil.h>
#include <net/netmsg2.h>
#include <net/ethernet.h>

#include <net/ipfw3/ip_fw.h>
#include <net/ipfw3_basic/ip_fw3_sync.h>

#define LEN_IN_ADDR		sizeof(struct in_addr)

MALLOC_DEFINE(M_IPFW3_SYNC, "IPFW3_SYNC", "mem for ipfw3sync");

extern struct ipfw3_context *fw3_ctx[MAXCPU];
extern struct ipfw3_sync_context fw3_sync_ctx;
ipfw_sync_send_state_t *ipfw_sync_send_state_prt = NULL;
ipfw_sync_install_state_t *ipfw_sync_install_state_prt = NULL;

/*
 * ipfw3sync show config
 */
int
ip_fw3_ctl_sync_show_conf(struct sockopt *sopt)
{
	struct ipfw3_ioc_sync_context *tmp_sync_ctx;
	int size;

	size = 3 * sizeof(int) + fw3_sync_ctx.count * LEN_SYNC_EDGE;
	if (sopt->sopt_valsize < size) {
		/* sopt_val is not big enough */
		bzero(sopt->sopt_val, sopt->sopt_valsize);
		return 0;
	}
	tmp_sync_ctx = (struct ipfw3_ioc_sync_context *)sopt->sopt_val;
	tmp_sync_ctx->edge_port = fw3_sync_ctx.edge_port;
	tmp_sync_ctx->hw_same = fw3_sync_ctx.hw_same;
	tmp_sync_ctx->count = fw3_sync_ctx.count;
	bcopy(fw3_sync_ctx.edges, tmp_sync_ctx->edges,
			fw3_sync_ctx.count * LEN_SYNC_EDGE);
	sopt->sopt_valsize = size;
	return 0;
}

/*
 * ipfw3sync show status
 */
int
ip_fw3_ctl_sync_show_status(struct sockopt *sopt)
{
	int *running;
	running = (int *)sopt->sopt_val;
	*running = fw3_sync_ctx.running;
	sopt->sopt_valsize = sizeof(int);
	return 0;
}
/*
 * ipfw3sync config centre
 */
int
ip_fw3_ctl_sync_centre_conf(struct sockopt *sopt)
{
	struct ipfw3_ioc_sync_centre *ioc_centre;
	int size;

	ioc_centre = sopt->sopt_val;
	size = ioc_centre->count * LEN_SYNC_EDGE;
	if (fw3_sync_ctx.count == 0) {
		fw3_sync_ctx.edges = kmalloc(size, M_IPFW3_SYNC, M_NOWAIT | M_ZERO);
	} else {
		fw3_sync_ctx.edges = krealloc(fw3_sync_ctx.edges,
				size, M_TEMP, M_WAITOK);
	}
	fw3_sync_ctx.count = ioc_centre->count;
	bcopy(ioc_centre->edges, fw3_sync_ctx.edges,
			ioc_centre->count * LEN_SYNC_EDGE);
	return 0;
}

/*
 * ipfw3sync config edge
 */
int
ip_fw3_ctl_sync_edge_conf(struct sockopt *sopt)
{
	struct ipfw3_ioc_sync_edge *ioc_edge;
	struct thread *td;
	size_t size;
	int error;

	size = sopt->sopt_valsize;
	ioc_edge = sopt->sopt_val;
	if (size != sizeof(struct ipfw3_ioc_sync_edge)) {
		return EINVAL;
	}
	fw3_sync_ctx.edge_port = ioc_edge->port;
	fw3_sync_ctx.hw_same = ioc_edge->hw_same;

	td = curthread->td_proc ? curthread : &thread0;
	error = socreate(AF_INET, &fw3_sync_ctx.edge_sock,
			SOCK_DGRAM, IPPROTO_UDP, td);
	if (error) {
		kprintf("ipfw3sync edge socreate failed: %d\n", error);
		return (error);
	}
	return 0;
}

void
sync_edge_socket_handler(void *dummy)
{
	struct socket *so;
	struct sockbuf sio;
	struct sockaddr_in sin;
	struct mbuf *m;
	struct sockaddr *sa;
	int error, flags, *type;

	so = fw3_sync_ctx.edge_sock;
	flags = MSG_FBLOCKING;

	bzero(&sin, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(fw3_sync_ctx.edge_port);
	sin.sin_len = LEN_IN_ADDR;
	sa = (struct sockaddr *)&sin;
	while (fw3_sync_ctx.running & 1) {
		sbinit(&sio, 1000000000);
		error = so_pru_soreceive(so, NULL, NULL, &sio, NULL, &flags);
		if (error)
			break;
		m = sio.sb_mb;
		type = (int *)m->m_data;
		if (*type == SYNC_TYPE_SEND_TEST) {
			struct cmd_send_test *cmd;
			cmd = (struct cmd_send_test *)m->m_data;
			kprintf("test received %d\n", cmd->num);
		} else if (*type == SYNC_TYPE_SEND_STATE) {
			struct cmd_send_state *cmd;
			cmd = (struct cmd_send_state *)m->m_data;
			if (ipfw_sync_install_state_prt != NULL) {
				(*ipfw_sync_install_state_prt)(cmd);
			}
		} else if (*type == SYNC_TYPE_SEND_NAT) {
			/* TODO sync NAT records */
			kprintf("nat received\n");
		} else {
			kprintf("Error ignore\n");
		}
	}
	soshutdown(fw3_sync_ctx.edge_sock, SHUT_RD);
	sofree(fw3_sync_ctx.edge_sock);
	kthread_exit();
}

int
ip_fw3_ctl_sync_edge_start(struct sockopt *sopt)
{
	struct sockaddr_in sin;
	struct thread *td;
	int error;

	if (fw3_sync_ctx.running & 1) {
		return 0;
	}
	td = curthread->td_proc ? curthread : &thread0;
	bzero(&sin, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_port = htons(fw3_sync_ctx.edge_port);
	sin.sin_addr.s_addr = INADDR_ANY;
	error = sobind(fw3_sync_ctx.edge_sock, (struct sockaddr *)&sin, td);
	if (error) {
		if (error != EADDRINUSE) {
			kprintf("ipfw3sync edge sobind failed: %d\n", error);
		} else {
			kprintf("ipfw3sync edge address in use: %d\n", error);
		}
		return (error);
	}

	fw3_sync_ctx.running |= 1;
	soreference(fw3_sync_ctx.edge_sock);
	error = kthread_create(sync_edge_socket_handler, NULL,
			&fw3_sync_ctx.edge_td, "sync_edge_thread");
	if (error) {
		panic("sync_edge_socket_handler:error %d",error);
	}
	return 0;
}

int
ip_fw3_ctl_sync_centre_start(struct sockopt *sopt)
{
	struct sockaddr_in sin;
	struct thread *td;
	struct ipfw3_sync_edge *edge;
	int error, i;

	fw3_sync_ctx.running |= 2;
	td = curthread->td_proc ? curthread : &thread0;

	for (i = 0; i < fw3_sync_ctx.count; i++) {
		error = socreate(AF_INET, &fw3_sync_ctx.centre_socks[i],
				SOCK_DGRAM, IPPROTO_UDP, td);
		if (error) {
			kprintf("ipfw3sync centre socreate failed: %d\n",
					error);
			return error;
		}
		edge = fw3_sync_ctx.edges;

		bzero(&sin, sizeof(struct sockaddr_in));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(edge->port);
		sin.sin_addr.s_addr = edge->addr;
		sin.sin_len = sizeof(struct sockaddr_in);
		error = soconnect(fw3_sync_ctx.centre_socks[i],
				(struct sockaddr *)&sin, td, TRUE);
		if (error) {
			kprintf("ipfw3sync: centre soconnect failed: %d\n",
					error);
			return error;
		}
	}

	return 0;
}

int
ip_fw3_ctl_sync_edge_test(struct sockopt *sopt)
{
	return 0;
}

int
ip_fw3_ctl_sync_centre_test(struct sockopt *sopt)
{
	struct cmd_send_test cmd;
	struct mbuf *m;
	struct thread *td;
	int error, i, len, nsize, *num;

	if (sopt->sopt_valsize != sizeof(int)) {
		kprintf("ipfw3sync: invalid centre test parameter\n");
		return -1;
	}
	if ((fw3_sync_ctx.running & 2) == 0) {
		kprintf("ipfw3sync: centre not running\n");
		return -1;
	}
	num = sopt->sopt_val;
	len = sizeof(struct cmd_send_test);
	m = m_getl(len, M_WAITOK, MT_DATA, M_PKTHDR, &nsize);
	if (m == NULL) {
		kprintf("ipfw3sync: MGET failed\n");
		return -1;
	}
	cmd.type = 0;
	cmd.num = *num;
	memcpy(m->m_data, &cmd, len);

	m->m_len = len;
	m->m_pkthdr.len = len;

	td = curthread->td_proc ? curthread : &thread0;
	for (i = 0; i < fw3_sync_ctx.count; i++) {
		error = so_pru_sosend(fw3_sync_ctx.centre_socks[i],
				NULL, NULL, m, NULL, 0 ,td);
		if (error) {
			kprintf("ipfw3sync: centre sosend failed: %d\n", error);
			return -1;
		}
	}
	m_free(m);
	return 0;
}
int
ip_fw3_ctl_sync_edge_stop(struct sockopt *sopt)
{
	if (fw3_sync_ctx.running & 1) {
		fw3_sync_ctx.running &= 2;
		soclose(fw3_sync_ctx.edge_sock, 0);
	}
	return 0;
}

int
ip_fw3_ctl_sync_centre_stop(struct sockopt *sopt)
{
	int i;

	if (fw3_sync_ctx.running & 2) {
		fw3_sync_ctx.running &= 1;
		for (i = 0; i < fw3_sync_ctx.count; i++) {
			soclose(fw3_sync_ctx.centre_socks[i], 0);
		}
	}
	return 0;
}

int
ip_fw3_ctl_sync_edge_clear(struct sockopt *sopt)
{
	return 0;
}

int
ip_fw3_ctl_sync_centre_clear(struct sockopt *sopt)
{
	return 0;
}

/*
 * sockopt handler
 */
int
ip_fw3_ctl_sync_sockopt(struct sockopt *sopt)
{
	int error = 0;
	switch (sopt->sopt_name) {
		case IP_FW_SYNC_EDGE_CONF:
			error = ip_fw3_ctl_sync_edge_conf(sopt);
			break;
		case IP_FW_SYNC_CENTRE_CONF:
			error = ip_fw3_ctl_sync_centre_conf(sopt);
			break;
		case IP_FW_SYNC_SHOW_CONF:
			error = ip_fw3_ctl_sync_show_conf(sopt);
			break;
		case IP_FW_SYNC_SHOW_STATUS:
			error = ip_fw3_ctl_sync_show_status(sopt);
			break;
		case IP_FW_SYNC_EDGE_START:
			error = ip_fw3_ctl_sync_edge_start(sopt);
			break;
		case IP_FW_SYNC_CENTRE_START:
			error = ip_fw3_ctl_sync_centre_start(sopt);
			break;
		case IP_FW_SYNC_EDGE_STOP:
			error = ip_fw3_ctl_sync_edge_stop(sopt);
			break;
		case IP_FW_SYNC_CENTRE_STOP:
			error = ip_fw3_ctl_sync_centre_stop(sopt);
			break;
		case IP_FW_SYNC_EDGE_CLEAR:
			error = ip_fw3_ctl_sync_edge_clear(sopt);
			break;
		case IP_FW_SYNC_CENTRE_CLEAR:
			error = ip_fw3_ctl_sync_centre_clear(sopt);
			break;
		case IP_FW_SYNC_EDGE_TEST:
			error = ip_fw3_ctl_sync_edge_test(sopt);
			break;
		case IP_FW_SYNC_CENTRE_TEST:
			error = ip_fw3_ctl_sync_centre_test(sopt);
			break;
		default:
			kprintf("ipfw3 sync invalid socket option %d\n",
					sopt->sopt_name);
	}
	return error;
}

void
ip_fw3_sync_send_state(struct ipfw3_state *state, int cpu, int hash)
{
	struct mbuf *m;
	struct thread *td;
	int error, i, len, nsize;
	struct cmd_send_state cmd;

	len = sizeof(struct cmd_send_state);
	m = m_getl(len, M_WAITOK, MT_DATA, M_PKTHDR, &nsize);
	if (m == NULL) {
		kprintf("ipfw3sync: MGET failed\n");
		return;
	}

	cmd.type = 1;
	cmd.cpu = cpu;
	cmd.hash = hash;

	memcpy(m->m_data, &cmd, len);

	m->m_len = len;
	m->m_pkthdr.len = len;

	td = curthread->td_proc ? curthread : &thread0;
	for (i = 0; i < fw3_sync_ctx.count; i++) {
		error = so_pru_sosend(fw3_sync_ctx.centre_socks[i],
				NULL, NULL, m, NULL, 0 ,td);
		if (error) {
			kprintf("ipfw3sync: centre sosend failed: %d\n", error);
			return;
		}
	}
	return;
}

void
ip_fw3_sync_modevent(int type)
{
	switch (type) {
		case MOD_LOAD:
			ipfw_sync_send_state_prt = ip_fw3_sync_send_state;
			break;
		case MOD_UNLOAD:
			if (fw3_sync_ctx.edges != NULL) {
				kfree(fw3_sync_ctx.edges, M_IPFW3_SYNC);
			}
			if (fw3_sync_ctx.running & 1) {
				fw3_sync_ctx.running = 0;
				soclose(fw3_sync_ctx.edge_sock, 0);
				fw3_sync_ctx.edge_td = NULL;
			}
			if (fw3_sync_ctx.running & 2) {
				int i;
				for (i = 0; i < fw3_sync_ctx.count; i++) {
					soclose(fw3_sync_ctx.centre_socks[i], 0);
				}
			}
			break;
		default:
			break;
	}
}

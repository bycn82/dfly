/*
 * Copyright (c) 2014 - 2016 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Bill Yuan <bycn82@dragonflybsd.org>
 *
 * Copyright (c) 2002 Luigi Rizzo
 * Copyright (c) 1996 Alex Nash, Paul Traina, Poul-Henning Kamp
 * Copyright (c) 1994 Ugen J.S.Antsilevich
 *
 * Idea and grammar partially left from:
 * Copyright (c) 1993 Daniel Boulet
 *
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
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
#include "ipfw3table.h"
#include "ipfw3dummynet.h"
#include "ipfw3state.h"
#include "ipfw3sync.h"
#include "ipfw3nat.h"


#define KEYWORD_SIZE	256
#define MAPPING_SIZE	256

#define MAX_KEYWORD_LEN	20
#define MAX_ARGS	32
#define WHITESP		" \t\f\v\n\r"
#define IPFW_LIB_PATH	"/usr/lib/libipfw3%s.so"

int		ipfw_socket = -1;	/* main RAW socket */
int		do_resolv, 		/* Would try to resolve all */
		do_acct, 		/* Show packet/byte count */
		do_time, 		/* Show time stamps */
		do_quiet = 1,		/* Be quiet , default is quiet*/
		do_force, 		/* Don't ask for confirmation */
		do_pipe, 		/* this cmd refers to a pipe */
		do_nat, 		/* Nat configuration. */
		do_sort, 		/* field to sort results (0 = no) */
		do_dynamic, 		/* display dynamic rules */
		do_expired, 		/* display expired dynamic rules */
		do_compact, 		/* show rules in compact mode */
		show_sets, 		/* display rule sets */
		verbose;

struct ipfw_keyword {
	int type;
	char word[MAX_KEYWORD_LEN];
	int module;
	int opcode;
};

struct ipfw_mapping {
	int type;
	int module;
	int opcode;
	parser_func parser;
	shower_func shower;
};

struct ipfw_keyword keywords[KEYWORD_SIZE];
struct ipfw_mapping mappings[MAPPING_SIZE];

int
match_token(struct char_int_map *table, char *string)
{
	while (table->key) {
		if (strcmp(table->key, string) == 0) {
			return table->val;
		}
		table++;
	}
	return 0;
}

static void
get_modules(char *modules_str, int len)
{
	if (do_get_x(IP_FW_MODULE, modules_str, &len) < 0)
		errx(EX_USAGE, "ipfw3 not loaded.");
}

static void
list_modules(int ac, char *av[])
{
	void *module_str = NULL;
	int len = 1024;
	if ((module_str = realloc(module_str, len)) == NULL)
		err(EX_OSERR, "realloc");

	get_modules(module_str, len);
	printf("%s\n", (char *)module_str);
}
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

static void
load_modules(void)
{
	const char *error;
	init_module mod_init_func;
	void *module_lib;
	char module_lib_file[50];
	void *module_str = NULL;
	int len = 1024;

	if ((module_str = realloc(module_str, len)) == NULL)
		err(EX_OSERR, "realloc");

	get_modules(module_str, len);

	const char s[2] = ",";
	char *token;
	token = strtok(module_str, s);
	while (token != NULL) {
		sprintf(module_lib_file, IPFW_LIB_PATH, token);
		token = strtok(NULL, s);
		module_lib = dlopen(module_lib_file, RTLD_LAZY);
		if (!module_lib) {
			fprintf(stderr, "Couldn't open %s: %s\n",
				module_lib_file, dlerror());
			exit(EX_SOFTWARE);
		}
		mod_init_func = dlsym(module_lib, "load_module");
		if ((error = dlerror()))
		{
			fprintf(stderr, "Couldn't find init function: %s\n", error);
			exit(EX_SOFTWARE);
		}
		(*mod_init_func)((register_func)register_ipfw_func,
				(register_keyword)register_ipfw_keyword);
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

void
register_ipfw_keyword(int module, int opcode, char *word, int type)
{
	struct ipfw_keyword *tmp;

	tmp=keywords;
	for (;;) {
		if (tmp->type == NONE) {
			strcpy(tmp->word, word);
			tmp->module = module;
			tmp->opcode = opcode;
			tmp->type = type;
			break;
		} else {
			if (strcmp(tmp->word, word) == 0)
				errx(EX_USAGE, "keyword `%s' exists", word);
			else
				tmp++;
		}
	}
}

void
register_ipfw_func(int module, int opcode, parser_func parser, shower_func shower)
{
	struct ipfw_mapping *tmp;

	tmp = mappings;
	while (1) {
		if (tmp->type == NONE) {
			tmp->module = module;
			tmp->opcode = opcode;
			tmp->parser = parser;
			tmp->shower = shower;
			tmp->type = IN_USE;
			break;
		} else {
			if (tmp->opcode == opcode && tmp->module == module) {
				errx(EX_USAGE, "func `%d' of module `%d' exists",
					opcode, module);
				break;
			} else {
				tmp++;
			}
		}
	}
}

/*
 * this func need to check whether 'or' need to be printed,
 * when the filter is the first filter with 'or' when dont print
 * when not first and same as previous, then print or and no filter name
 * when not first but different from previous, print name without 'or'
 * show_or = 1: show or and ignore filter name
 * show_or = 0: show filter name ignore or
 */
void prev_show_chk(ipfw_insn *cmd, uint8_t *prev_module, uint8_t *prev_opcode,
		int *show_or)
{
	if (cmd->len & F_OR) {
		if (*prev_module == 0 && *prev_opcode == 0) {
			/* first cmd with 'or' flag */
			*show_or = 0;
			*prev_module = cmd->module;
			*prev_opcode = cmd->opcode;
		} else if (cmd->module == *prev_module &&
				cmd->opcode == *prev_opcode) {
			/* cmd same as previous, same module and opcode */
			*show_or = 1;
		} else {
			/* cmd different from prev*/
			*show_or = 0;
			*prev_module = cmd->module;
			*prev_opcode = cmd->opcode;

		}
	} else {
		*show_or = 0;
		*prev_module = 0;
		*prev_opcode = 0;
	}
}

/*
 * word can be: proto from to other
 * proto show proto
 * from show from
 * to show to
 * other show all other filters
 */
int show_filter(ipfw_insn *cmd, char *word, int type)
{
	struct ipfw_keyword *k;
	struct ipfw_mapping *m;
	shower_func fn;
	int i, j, show_or;
	uint8_t prev_module, prev_opcode;

	k = keywords;
	m = mappings;
	for (i = 1; i < KEYWORD_SIZE; i++, k++) {
		if (k->type == type) {
			if (k->module == cmd->module &&
					k->opcode == cmd->opcode) {
				for (j = 1; j < MAPPING_SIZE; j++, m++) {
					if (m->type == IN_USE &&
						k->module == m->module &&
						k->opcode == m->opcode) {
						prev_show_chk(cmd, &prev_module,
							&prev_opcode, &show_or);
						if (cmd->len & F_NOT)
							printf(" not");

						fn = m->shower;
						(*fn)(cmd, show_or);
						return 1;
					}
				}
			}
		}
	}
	return 0;
}

static void
show_rules(struct ipfw_ioc_rule *rule, int pcwidth, int bcwidth)
{
	static int twidth = 0;
	ipfw_insn *cmd;
	int l;

	u_int32_t set_disable = rule->set_disable;

	if (set_disable & (1 << rule->set)) { /* disabled */
		if (!show_sets)
			return;
		else
			printf("# DISABLED ");
	}
	printf("%05u ", rule->rulenum);

	if (do_acct)
		printf("%*ju %*ju ", pcwidth, (uintmax_t)rule->pcnt, bcwidth,
			(uintmax_t)rule->bcnt);

	if (do_time == 1) {
		char timestr[30];

		if (twidth == 0) {
			strcpy(timestr, ctime((time_t *)&twidth));
			*strchr(timestr, '\n') = '\0';
			twidth = strlen(timestr);
		}
		if (rule->timestamp) {
			time_t t = _long_to_time(rule->timestamp);

			strcpy(timestr, ctime(&t));
			*strchr(timestr, '\n') = '\0';
			printf("%s ", timestr);
		} else {
			printf("%*s ", twidth, " ");
		}
	} else if (do_time == 2) {
		printf( "%10u ", rule->timestamp);
	}

	if (show_sets)
		printf("set %d ", rule->set);


	struct ipfw_keyword *k;
	struct ipfw_mapping *m;
	shower_func fn, comment_fn = NULL;
	ipfw_insn *comment_cmd;
	int i, j, changed;

	/*
	 * show others and actions
	 */
	for (l = rule->cmd_len - rule->act_ofs, cmd = ACTION_PTR(rule);
		l > 0; l -= F_LEN(cmd),
		cmd = (ipfw_insn *)((uint32_t *)cmd + F_LEN(cmd))) {
		k = keywords;
		m = mappings;
		for (i = 1; i< KEYWORD_SIZE; i++, k++) {
			if ( k->module == cmd->module && k->opcode == cmd->opcode ) {
				for (j = 1; j< MAPPING_SIZE; j++, m++) {
					if (m->type == IN_USE &&
						m->module == cmd->module &&
						m->opcode == cmd->opcode) {
						if (cmd->module == MODULE_BASIC_ID &&
							cmd->opcode == O_BASIC_COMMENT) {
							comment_fn = m->shower;
							comment_cmd = cmd;
						} else {
							fn = m->shower;
							(*fn)(cmd, 0);
						}
						if (cmd->module == MODULE_BASIC_ID &&
							cmd->opcode ==
								O_BASIC_CHECK_STATE) {
							goto done;
						}
						break;
					}
				}
				break;
			}
		}
	}

	/*
	 * show proto
	 */
	changed=0;
	for (l = rule->act_ofs, cmd = rule->cmd; l > 0; l -= F_LEN(cmd),
			cmd = (ipfw_insn *)((uint32_t *)cmd + F_LEN(cmd))) {
		changed = show_filter(cmd, "proto", PROTO);
	}
	if (!changed && !do_quiet)
		printf(" ip");

	/*
	 * show from
	 */
	changed = 0;
	for (l = rule->act_ofs, cmd = rule->cmd; l > 0; l -= F_LEN(cmd),
			cmd = (ipfw_insn *)((uint32_t *)cmd + F_LEN(cmd))) {
		changed = show_filter(cmd, "from", FROM);
	}
	if (!changed && !do_quiet)
		printf(" from any");

	/*
	 * show to
	 */
	changed = 0;
	for (l = rule->act_ofs, cmd = rule->cmd; l > 0; l -= F_LEN(cmd),
			cmd = (ipfw_insn *)((uint32_t *)cmd + F_LEN(cmd))) {
		changed = show_filter(cmd, "to", TO);
	}
	if (!changed && !do_quiet)
		printf(" to any");

	/*
	 * show other filters
	 */
	for (l = rule->act_ofs, cmd = rule->cmd, m = mappings;
			l > 0; l -= F_LEN(cmd),
			cmd=(ipfw_insn *)((uint32_t *)cmd + F_LEN(cmd))) {
		show_filter(cmd, "other", FILTER);
	}

	/* show the comment in the end */
	if (comment_fn != NULL) {
		(*comment_fn)(comment_cmd, 0);
	}
done:
	printf("\n");
}

static void
show_states(struct ipfw_ioc_state *d, int pcwidth, int bcwidth)
{
	struct protoent *pe;
	struct in_addr a;

	printf("%05u ", d->rulenum);
	if (do_acct) {
		printf("%*ju %*ju ", pcwidth, (uintmax_t)d->pcnt,
				bcwidth, (uintmax_t)d->bcnt);
	}

	if (do_time == 1) {
		/* state->timestamp */
		char timestr[30];
		time_t t = _long_to_time(d->timestamp);
		strcpy(timestr, ctime(&t));
		*strchr(timestr, '\n') = '\0';
		printf(" (%s", timestr);

		/* state->lifetime */
		printf(" %ds", d->lifetime);

		/* state->expiry */
		if (d->expiry !=0) {
			t = _long_to_time(d->expiry);
			strcpy(timestr, ctime(&t));
			*strchr(timestr, '\n') = '\0';
			printf(" %s)", timestr);
		} else {
			printf(" 0)");
		}

	} else if (do_time == 2) {
		printf("(%u %ds %u) ", d->timestamp, d->lifetime, d->expiry);
	}

	if ((pe = getprotobynumber(d->flow_id.proto)) != NULL)
		printf(" %s", pe->p_name);
	else
		printf(" proto %u", d->flow_id.proto);

	a.s_addr = htonl(d->flow_id.src_ip);
	printf(" %s %d", inet_ntoa(a), d->flow_id.src_port);

	a.s_addr = htonl(d->flow_id.dst_ip);
	printf(" <-> %s %d", inet_ntoa(a), d->flow_id.dst_port);
	printf(" CPU %d", d->cpuid);
	printf("\n");
}



/*
 * This one handles all set-related commands
 * 	ipfw set { show | enable | disable }
 * 	ipfw set swap X Y
 * 	ipfw set move X to Y
 * 	ipfw set move rule X to Y
 */
static void
sets_handler(int ac, char *av[])
{
	u_int32_t set_disable, masks[2];
	u_int16_t rulenum;
	u_int8_t cmd, new_set;
	int i, nbytes;

	NEXT_ARG;
	if (!ac)
		errx(EX_USAGE, "set needs command");
	if (!strncmp(*av, "show", strlen(*av)) ) {
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
	} else if (!strncmp(*av, "swap", strlen(*av))) {
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
	} else if (!strncmp(*av, "disable", strlen(*av)) ||
			!strncmp(*av, "enable", strlen(*av)) ) {
		int which = !strncmp(*av, "enable", strlen(*av)) ? 1 : 0;

		NEXT_ARG;
		masks[0] = masks[1] = 0;

		while (ac) {
			if (isdigit(**av)) {
				i = atoi(*av);
				if (i < 0 || i > 30)
					errx(EX_DATAERR, "invalid set number %d\n", i);
				masks[which] |= (1<<i);
			} else if (!strncmp(*av, "disable", strlen(*av)))
				which = 0;
			else if (!strncmp(*av, "enable", strlen(*av)))
				which = 1;
			else
				errx(EX_DATAERR, "invalid set command %s\n", *av);
			NEXT_ARG;
		}
		if ( (masks[0] & masks[1]) != 0 )
			errx(EX_DATAERR, "cannot enable and disable the same set\n");
		i = do_set_x(IP_FW_DEL, masks, sizeof(masks));
		if (i)
			warn("set enable/disable: setsockopt(IP_FW_DEL)");
	} else
		errx(EX_USAGE, "invalid set command %s\n", *av);
}

static void
list(int ac, char *av[])
{
	struct ipfw_ioc_state *dynrules, *d;
	struct ipfw_ioc_rule *r;

	u_long rnum;
	void *data = NULL;
	int bcwidth, n, nbytes, nstat, ndyn, pcwidth, width;
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
	dynrules = (struct ipfw_ioc_state *)((void *)r + r->static_len);
	ndyn = (nbytes - r->static_len) / sizeof(*dynrules);

	/* if showing stats, figure out column widths ahead of time */
	bcwidth = pcwidth = 0;
	if (do_acct) {
		for (n = 0, r = data; n < nstat;
			n++, r = (void *)r + IOC_RULESIZE(r)) {
			/* packet counter */
			width = snprintf(NULL, 0, "%ju", (uintmax_t)r->pcnt);
			if (width > pcwidth)
				pcwidth = width;

			/* byte counter */
			width = snprintf(NULL, 0, "%ju", (uintmax_t)r->bcnt);
			if (width > bcwidth)
				bcwidth = width;
		}
	}
	if (do_dynamic && ndyn) {
		for (n = 0, d = dynrules; n < ndyn; n++, d++) {
			width = snprintf(NULL, 0, "%ju", (uintmax_t)d->pcnt);
			if (width > pcwidth)
				pcwidth = width;

			width = snprintf(NULL, 0, "%ju", (uintmax_t)d->bcnt);
			if (width > bcwidth)
				bcwidth = width;
		}
	}

	/* if no rule numbers were specified, list all rules */
	if (ac == 0) {
		if (do_dynamic != 2) {
			for (n = 0, r = data; n < nstat; n++,
				r = (void *)r + IOC_RULESIZE(r)) {
				show_rules(r, pcwidth, bcwidth);
			}
		}
		if (do_dynamic && ndyn) {
			if (do_dynamic != 2) {
				printf("## States (%d):\n", ndyn);
			}
			for (n = 0, d = dynrules; n < ndyn; n++, d++)
				show_states(d, pcwidth, bcwidth);
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
				if (r->rulenum == rnum) {
					show_rules(r, pcwidth, bcwidth);
					seen = 1;
				}
			}
			if (!seen) {
				/* give precedence to other error(s) */
				if (exitval == EX_OK)
					exitval = EX_UNAVAILABLE;
				warnx("rule %lu does not exist", rnum);
			}
		}
	}

	if (do_dynamic && ndyn) {
		if (do_dynamic != 2) {
			printf("## States (%d):\n", ndyn);
		}
		for (lac = ac, lav = av; lac != 0; lac--) {
			rnum = strtoul(*lav++, &endptr, 10);
			if (*endptr)
				/* already warned */
				continue;
			for (n = 0, d = dynrules; n < ndyn; n++, d++) {
				if (d->rulenum > rnum)
					break;
				if (d->rulenum == rnum)
					show_states(d, pcwidth, bcwidth);
			}
		}
	}

	ac = 0;

done:
	free(data);

	if (exitval != EX_OK)
		exit(exitval);
}



static void
help(void)
{
	fprintf(stderr, "usage: ipfw [options]\n"
			"	ipfw add [rulenum] [set id] action filters\n"
			"	ipfw delete [rulenum]\n"
			"	ipfw flush\n"
			"	ipfw list [rulenum]\n"
			"	ipfw show [rulenum]\n"
			"	ipfw zero [rulenum]\n"
			"	ipfw set [show|enable|disable]\n"
			"	ipfw module\n"
			"	ipfw [enable|disable]\n"
			"	ipfw log [reset|off|on]\n"
			"	ipfw nat [config|show|delete]\n"
			"	ipfw pipe [config|show|delete]\n"
			"	ipfw state [add|delete|list|show]"
			"\nsee ipfw manpage for details\n");
	exit(EX_USAGE);
}


static void
delete_rules(int ac, char *av[])
{
	struct dn_ioc_pipe pipe;
	u_int32_t rulenum;
	int exitval = EX_OK;
	int do_set = 0;
	int i;

	memset(&pipe, 0, sizeof pipe);

	NEXT_ARG;
	if (ac > 0 && !strncmp(*av, "set", strlen(*av))) {
		do_set = 1; 	/* delete set */
		NEXT_ARG;
	}

	/* Rule number */
	while (ac && isdigit(**av)) {
		i = atoi(*av);
		NEXT_ARG;
		if (do_pipe) {
			if (do_pipe == 1)
				pipe.pipe_nr = i;
			else
				pipe.fs.fs_nr = i;

			i = do_set_x(IP_DUMMYNET_DEL, &pipe, sizeof pipe);
			if (i) {
				exitval = 1;
				warn("rule %u: setsockopt(IP_DUMMYNET_DEL)",
					do_pipe == 1 ? pipe.pipe_nr :
					pipe.fs.fs_nr);
			}
		} else {
			rulenum = (i & 0xffff) | (do_set << 24);
			i = do_set_x(IP_FW_DEL, &rulenum, sizeof rulenum);
			if (i) {
				exitval = EX_UNAVAILABLE;
				warn("rule %u: setsockopt(IP_FW_DEL)",
					rulenum);
			}
		}
	}
	if (exitval != EX_OK)
		exit(exitval);
}


/*
 * helper function, updates the pointer to cmd with the length
 * of the current command, and also cleans up the first word of
 * the new command in case it has been clobbered before.
 */
static ipfw_insn*
next_cmd(ipfw_insn *cmd)
{
	cmd += F_LEN(cmd);
	bzero(cmd, sizeof(*cmd));
	return cmd;
}

/*
 * Parse arguments and assemble the microinstructions which make up a rule.
 * Rules are added into the 'rulebuf' and then copied in the correct order
 * into the actual rule.
 *
 *
 */
static void
add(int ac, char *av[])
{
	/*
	 * rules are added into the 'rulebuf' and then copied in
	 * the correct order into the actual rule.
	 * Some things that need to go out of order (prob, action etc.)
	 * go into actbuf[].
	 */
	static uint32_t rulebuf[IPFW_RULE_SIZE_MAX];
	static uint32_t actbuf[IPFW_RULE_SIZE_MAX];
	static uint32_t othbuf[IPFW_RULE_SIZE_MAX];
	static uint32_t cmdbuf[IPFW_RULE_SIZE_MAX];

	ipfw_insn *src, *dst, *cmd, *action, *other;
	ipfw_insn *prev;
	char *prev_av;
	ipfw_insn *the_comment = NULL;
	struct ipfw_ioc_rule *rule;
	struct ipfw_keyword *key;
	struct ipfw_mapping *map;
	parser_func fn;
	int i, j;

	bzero(actbuf, sizeof(actbuf)); 		/* actions go here */
	bzero(othbuf, sizeof(actbuf)); 		/* others */
	bzero(cmdbuf, sizeof(cmdbuf)); 		/* filters */
	bzero(rulebuf, sizeof(rulebuf));

	rule = (struct ipfw_ioc_rule *)rulebuf;
	cmd = (ipfw_insn *)cmdbuf;
	action = (ipfw_insn *)actbuf;
	other = (ipfw_insn *)othbuf;

	NEED2("need more parameters");
	NEXT_ARG;

	/* [rule N]	-- Rule number optional */
	if (ac && isdigit(**av)) {
		rule->rulenum = atoi(*av);
		NEXT_ARG;
	}

	/* [set N]	-- set number (0..30), optional */
	if (ac > 1 && !strncmp(*av, "set", strlen(*av))) {
		int set = strtoul(av[1], NULL, 10);
		if (set < 0 || set > 30)
			errx(EX_DATAERR, "illegal set %s", av[1]);
		rule->set = set;
		av += 2; ac -= 2;
	}

	/*
	 * parse before
	 */
	for (;;) {
		for (i = 0, key = keywords; i < KEYWORD_SIZE; i++, key++) {
			if (key->type == BEFORE &&
				strcmp(key->word, *av) == 0) {
				for (j = 0, map = mappings;
					j < MAPPING_SIZE; j++, map++) {
					if (map->type == IN_USE &&
						map->module == key->module &&
						map->opcode == key->opcode ) {
						fn = map->parser;
						(*fn)(&other, &ac, &av);
						break;
					}
				}
				break;
			}
		}
		if (i >= KEYWORD_SIZE) {
			break;
		} else if (F_LEN(other) > 0) {
			if (other->module == MODULE_BASIC_ID &&
				other->opcode == O_BASIC_CHECK_STATE) {
				other = next_cmd(other);
				goto done;
			}
			other = next_cmd(other);
		}
	}

	/*
	 * parse actions
	 *
	 * only accept 1 action
	 */
	NEED1("missing action");
	for (i = 0, key = keywords; i < KEYWORD_SIZE; i++, key++) {
		if (ac > 0 && key->type == ACTION &&
			strcmp(key->word, *av) == 0) {
			for (j = 0, map = mappings;
					j < MAPPING_SIZE; j++, map++) {
				if (map->type == IN_USE &&
					map->module == key->module &&
					map->opcode == key->opcode) {
					fn = map->parser;
					(*fn)(&action, &ac, &av);
					break;
				}
			}
			break;
		}
	}
	if (F_LEN(action) > 0)
		action = next_cmd(action);

	/*
	 * parse protocol
	 */
	if (strcmp(*av, "proto") == 0){
		NEXT_ARG;
	}

	NEED1("missing protocol");
	for (i = 0, key = keywords; i < KEYWORD_SIZE; i++, key++) {
		if (key->type == PROTO &&
			strcmp(key->word, "proto") == 0) {
			for (j = 0, map = mappings;
					j < MAPPING_SIZE; j++, map++) {
				if (map->type == IN_USE &&
					map->module == key->module &&
					map->opcode == key->opcode ) {
					fn = map->parser;
					(*fn)(&cmd, &ac, &av);
					break;
				}
			}
			break;
		}
	}
	if (F_LEN(cmd) > 0)
		cmd = next_cmd(cmd);

	/*
	 * other filters
	 */
	while (ac > 0) {
		char *s, *cur;		/* current filter */
		ipfw_insn_u32 *cmd32; 	/* alias for cmd */

		s = *av;
		cmd32 = (ipfw_insn_u32 *)cmd;
		if (strcmp(*av, "or") == 0) {
			if (prev == NULL)
				errx(EX_USAGE, "'or' should"
						"between two filters\n");
			prev->len |= F_OR;
			cmd->len = F_OR;
			*av = prev_av;
		}
		if (strcmp(*av, "not") == 0) {
			if (cmd->len & F_NOT)
				errx(EX_USAGE, "double \"not\" not allowed\n");
			cmd->len = F_NOT;
			NEXT_ARG;
			continue;
		}
		cur = *av;
		for (i = 0, key = keywords; i < KEYWORD_SIZE; i++, key++) {
			if ((key->type == FILTER ||
                                key->type == AFTER ||
                                key->type == FROM ||
                                key->type == TO) &&
				strcmp(key->word, cur) == 0) {
				for (j = 0, map = mappings;
					j< MAPPING_SIZE; j++, map++) {
					if (map->type == IN_USE &&
						map->module == key->module &&
						map->opcode == key->opcode ) {
						fn = map->parser;
						(*fn)(&cmd, &ac, &av);
						break;
					}
				}
				break;
			} else if (i == KEYWORD_SIZE - 1) {
				errx(EX_USAGE, "bad command `%s'", cur);
			}
		}
		if (i >= KEYWORD_SIZE) {
			break;
		} else if (F_LEN(cmd) > 0) {
			prev = cmd;
			prev_av = cur;
			cmd = next_cmd(cmd);
		}
	}

done:
	if (ac>0)
		errx(EX_USAGE, "bad command `%s'", *av);

	/*
	 * Now copy stuff into the rule.
	 * [filters][others][action][comment]
	 */
	dst = (ipfw_insn *)rule->cmd;
	/*
	 * copy all filters, except comment
	 */
	src = (ipfw_insn *)cmdbuf;
	for (src = (ipfw_insn *)cmdbuf; src != cmd; src += i) {
		/* pick comment out */
		i = F_LEN(src);
		if (src->module == MODULE_BASIC_ID &&
				src->opcode == O_BASIC_COMMENT) {
			the_comment=src;
		} else {
			bcopy(src, dst, i * sizeof(u_int32_t));
			dst = (ipfw_insn *)((uint32_t *)dst + i);
		}
	}

	/*
	 * start action section, it begin with others
	 */
	rule->act_ofs = (uint32_t *)dst - (uint32_t *)(rule->cmd);

	/*
	 * copy all other others
	 */
	for (src = (ipfw_insn *)othbuf; src != other; src += i) {
		i = F_LEN(src);
		bcopy(src, dst, i * sizeof(u_int32_t));
		dst = (ipfw_insn *)((uint32_t *)dst + i);
	}

	/* copy the action to the end of rule */
	src = (ipfw_insn *)actbuf;
	i = F_LEN(src);
	bcopy(src, dst, i * sizeof(u_int32_t));
	dst = (ipfw_insn *)((uint32_t *)dst + i);

	/*
	 * comment place behind the action
	 */
	if (the_comment != NULL) {
		i = F_LEN(the_comment);
		bcopy(the_comment, dst, i * sizeof(u_int32_t));
		dst = (ipfw_insn *)((uint32_t *)dst + i);
	}

	rule->cmd_len = (u_int32_t *)dst - (u_int32_t *)(rule->cmd);
	i = (void *)dst - (void *)rule;
	if (do_set_x(IP_FW_ADD, (void *)rule, i) == -1) {
		err(EX_UNAVAILABLE, "getsockopt(%s)", "IP_FW_ADD");
	}
	if (!do_quiet)
		show_rules(rule, 10, 10);
}

static void
zero(int ac, char *av[])
{
	int rulenum;
	int failed = EX_OK;

	NEXT_ARG;

	if (!ac) {
		/* clear all entries */
		if (do_set_x(IP_FW_ZERO, NULL, 0) < 0)
			err(EX_UNAVAILABLE, "do_set_x(IP_FW_ZERO)");
		if (!do_quiet)
			printf("Accounting cleared.\n");
		return;
	}

	while (ac) {
		/* Rule number */
		if (isdigit(**av)) {
			rulenum = atoi(*av);
			NEXT_ARG;
			if (do_set_x(IP_FW_ZERO, &rulenum, sizeof rulenum)) {
				warn("rule %u: do_set_x(IP_FW_ZERO)", rulenum);
				failed = EX_UNAVAILABLE;
			} else if (!do_quiet)
				printf("Entry %d cleared\n", rulenum);
		} else {
			errx(EX_USAGE, "invalid rule number ``%s''", *av);
		}
	}
	if (failed != EX_OK)
		exit(failed);
}

static void
resetlog(int ac, char *av[])
{
	int rulenum;
	int failed = EX_OK;

	NEXT_ARG;

	if (!ac) {
		/* clear all entries */
		if (setsockopt(ipfw_socket, IPPROTO_IP,
					IP_FW_RESETLOG, NULL, 0) < 0)
			err(EX_UNAVAILABLE, "setsockopt(IP_FW_RESETLOG)");
		if (!do_quiet)
			printf("Logging counts reset.\n");

		return;
	}

	while (ac) {
		/* Rule number */
		if (isdigit(**av)) {
			rulenum = atoi(*av);
			NEXT_ARG;
			if (setsockopt(ipfw_socket, IPPROTO_IP,
				IP_FW_RESETLOG, &rulenum, sizeof rulenum)) {
				warn("rule %u: setsockopt(IP_FW_RESETLOG)",
						rulenum);
				failed = EX_UNAVAILABLE;
			} else if (!do_quiet)
				printf("Entry %d logging count reset\n",
						rulenum);
		} else {
			errx(EX_DATAERR, "invalid rule number ``%s''", *av);
		}
	}
	if (failed != EX_OK)
		exit(failed);
}

static void
flush(void)
{
	int cmd = IP_FW_FLUSH;
	if (do_pipe) {
		cmd = IP_DUMMYNET_FLUSH;
	}
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
	if (do_set_x(cmd, NULL, 0) < 0 ) {
		if (do_pipe)
			errx(EX_USAGE, "pipe/queue in use");
		else
			errx(EX_USAGE, "do_set_x(IP_FW_FLUSH) failed");
	}
	if (!do_quiet) {
		printf("Flushed all %s.\n", do_pipe ? "pipes" : "rules");
	}
}

/*
 * do_set_x - extended version og do_set
 * insert a x_header in the beginning of the rule buf
 * and call setsockopt() with IP_FW_X.
 */
int
do_set_x(int optname, void *rule, int optlen)
{
	int len, *newbuf;

	ip_fw_x_header *x_header;
	if (ipfw_socket < 0)
		err(EX_UNAVAILABLE, "socket not avaialble");
	len = optlen + sizeof(ip_fw_x_header);
	newbuf = malloc(len);
	if (newbuf == NULL)
		err(EX_OSERR, "malloc newbuf in do_set_x");
	bzero(newbuf, len);
	x_header = (ip_fw_x_header *)newbuf;
	x_header->opcode = optname;
	/* copy the rule into the newbuf, just after the x_header*/
	bcopy(rule, ++x_header, optlen);
	return setsockopt(ipfw_socket, IPPROTO_IP, IP_FW_X, newbuf, len);
}

/*
 * same as do_set_x
 */
int
do_get_x(int optname, void *rule, int *optlen)
{
	int len, *newbuf, retval;

	ip_fw_x_header *x_header;
	if (ipfw_socket < 0)
		err(EX_UNAVAILABLE, "socket not avaialble");
	len = *optlen + sizeof(ip_fw_x_header);
	newbuf = malloc(len);
	if (newbuf == NULL)
		err(EX_OSERR, "malloc newbuf in do_get_x");
	bzero(newbuf, len);
	x_header = (ip_fw_x_header *)newbuf;
	x_header->opcode = optname;
	/* copy the rule into the newbuf, just after the x_header*/
	bcopy(rule, ++x_header, *optlen);
	retval = getsockopt(ipfw_socket, IPPROTO_IP, IP_FW_X, newbuf, &len);
	bcopy(newbuf, rule, len);
	*optlen=len;
	return retval;
}

static int
ipfw_main(int ac, char **av)
{
	int ch;

	if (ac == 1)
		help();

	/* Set the force flag for non-interactive processes */
	do_force = !isatty(STDIN_FILENO);

	optind = optreset = 1;
	while ((ch = getopt(ac, av, "hs:acdDefNStTv")) != -1)
		switch (ch) {
		case 'h': /* help */
			help();
			break; 	/* NOTREACHED */

		case 's': /* sort */
			do_sort = atoi(optarg);
			break;
		case 'a':
			do_acct = 1;
			break;
		case 'c':
			do_compact = 1;
			break;
		case 'd':
			do_dynamic = 1;
			break;
		case 'D':
			do_dynamic = 2;
			break;
		case 'e':
			do_expired = 1;
			break;
		case 'f':
			do_force = 1;
			break;
		case 'N':
			do_resolv = 1;
			break;
		case 'S':
			show_sets = 1;
			break;
		case 't':
			do_time = 1;
			break;
		case 'T':
			do_time = 2;
			break;
		case 'v':
			do_quiet = 0;
			verbose++;
			break;
		default:
			help();
		}

	ac -= optind;
	av += optind;
	NEED1("bad arguments, for usage summary ``ipfw''");

	/*
	 * optional: pipe or queue or nat
	 */
	do_nat = 0;
	do_pipe = 0;
	if (!strncmp(*av, "nat", strlen(*av)))
		do_nat = 1;
	else if (!strncmp(*av, "pipe", strlen(*av))) {
		do_pipe = 1;
	} else if (!strncmp(*av, "queue", strlen(*av))) {
		do_pipe = 2;
	}
	NEED1("missing command");

	/*
	 * for pipes and queues and nat we normally say 'pipe NN config'
	 * but the code is easier to parse as 'pipe config NN'
	 * so we swap the two arguments.
	 */
	if ((do_pipe || do_nat) && ac > 2 && isdigit(*(av[1]))) {
		char *p = av[1];
		av[1] = av[2];
		av[2] = p;
	}

	if (!strncmp(*av, "add", strlen(*av))) {
		load_modules();
		add(ac, av);
	} else if (!strncmp(*av, "delete", strlen(*av))) {
		delete_rules(ac, av);
	} else if (!strncmp(*av, "flush", strlen(*av))) {
		flush();
	} else if (!strncmp(*av, "list", strlen(*av))) {
		load_modules();
		list(ac, av);
	} else if (!strncmp(*av, "show", strlen(*av))) {
		do_acct++;
		load_modules();
		list(ac, av);
	} else if (!strncmp(*av, "zero", strlen(*av))) {
		zero(ac, av);
	} else if (!strncmp(*av, "set", strlen(*av))) {
		sets_handler(ac, av);
	} else if (!strncmp(*av, "module", strlen(*av))) {
		NEXT_ARG;
		if (!strncmp(*av, "list", strlen(*av))) {
			list_modules(ac, av);
		} else {
			errx(EX_USAGE, "bad ipfw module command `%s'", *av);
		}
	} else if (!strncmp(*av, "resetlog", strlen(*av))) {
		resetlog(ac, av);
	} else if (!strncmp(*av, "log", strlen(*av))) {
		NEXT_ARG;
		if (!strncmp(*av, "reset", strlen(*av))) {
			resetlog(ac, av);
		} else if (!strncmp(*av, "off", strlen(*av))) {

		} else if (!strncmp(*av, "on", strlen(*av))) {

		} else {
			errx(EX_USAGE, "bad command `%s'", *av);
		}
	} else if (!strncmp(*av, "nat", strlen(*av))) {
		NEXT_ARG;
		nat_main(ac, av);
	} else if (!strncmp(*av, "pipe", strlen(*av)) ||
		!strncmp(*av, "queue", strlen(*av))) {
		NEXT_ARG;
		dummynet_main(ac, av);
	} else if (!strncmp(*av, "state", strlen(*av))) {
		NEXT_ARG;
		state_main(ac, av);
	} else if (!strncmp(*av, "table", strlen(*av))) {
		if (ac > 2 && isdigit(*(av[1]))) {
			char *p = av[1];
			av[1] = av[2];
			av[2] = p;
		}
		NEXT_ARG;
		table_main(ac, av);
	} else if (!strncmp(*av, "sync", strlen(*av))) {
		NEXT_ARG;
		sync_main(ac, av);
	} else {
		errx(EX_USAGE, "bad ipfw command `%s'", *av);
	}
	return 0;
}

static void
ipfw_readfile(int ac, char *av[])
{
	char	buf[BUFSIZ];
	char	*a, *p, *args[MAX_ARGS], *cmd = NULL;
	char	linename[17];
	int	i=0, lineno=0, qflag=0, pflag=0, status;
	FILE	*f = NULL;
	pid_t	preproc = 0;
	int	c;

	while ((c = getopt(ac, av, "D:U:p:q")) != -1) {
		switch (c) {
		case 'D':
			if (!pflag)
				errx(EX_USAGE, "-D requires -p");
			if (i > MAX_ARGS - 2)
				errx(EX_USAGE, "too many -D or -U options");
			args[i++] = "-D";
			args[i++] = optarg;
			break;

		case 'U':
			if (!pflag)
				errx(EX_USAGE, "-U requires -p");
			if (i > MAX_ARGS - 2)
				errx(EX_USAGE, "too many -D or -U options");
			args[i++] = "-U";
			args[i++] = optarg;
			break;

		case 'p':
			pflag = 1;
			cmd = optarg;
			args[0] = cmd;
			i = 1;
			break;

		case 'q':
			qflag = 1;
			break;

		default:
			errx(EX_USAGE, "bad arguments, for usage"
			    " summary ``ipfw''");
		}
	}

	av += optind;
	ac -= optind;
	if (ac != 1)
		errx(EX_USAGE, "extraneous filename arguments");

	if ((f = fopen(av[0], "r")) == NULL)
		err(EX_UNAVAILABLE, "fopen: %s", av[0]);

	if (pflag) {
		/* pipe through preprocessor (cpp or m4) */
		int pipedes[2];

		args[i] = NULL;

		if (pipe(pipedes) == -1)
			err(EX_OSERR, "cannot create pipe");

		switch ((preproc = fork())) {
		case -1:
			err(EX_OSERR, "cannot fork");

		case 0:
			/* child */
			if (dup2(fileno(f), 0) == -1 ||
			    dup2(pipedes[1], 1) == -1) {
				err(EX_OSERR, "dup2()");
			}
			fclose(f);
			close(pipedes[1]);
			close(pipedes[0]);
			execvp(cmd, args);
			err(EX_OSERR, "execvp(%s) failed", cmd);

		default:
			/* parent */
			fclose(f);
			close(pipedes[1]);
			if ((f = fdopen(pipedes[0], "r")) == NULL) {
				int savederrno = errno;

				kill(preproc, SIGTERM);
				errno = savederrno;
				err(EX_OSERR, "fdopen()");
			}
		}
	}

	while (fgets(buf, BUFSIZ, f)) {
		lineno++;
		sprintf(linename, "Line %d", lineno);
		args[0] = linename;

		if (*buf == '#')
			continue;
		if ((p = strchr(buf, '#')) != NULL)
			*p = '\0';
		i = 1;
		if (qflag)
			args[i++] = "-q";
		for (a = strtok(buf, WHITESP); a && i < MAX_ARGS;
			a = strtok(NULL, WHITESP), i++) {
			args[i] = a;
		}

		if (i == (qflag? 2: 1))
			continue;
		if (i == MAX_ARGS)
			errx(EX_USAGE, "%s: too many arguments", linename);

		args[i] = NULL;
		ipfw_main(i, args);
	}
	fclose(f);
	if (pflag) {
		if (waitpid(preproc, &status, 0) == -1)
			errx(EX_OSERR, "waitpid()");
		if (WIFEXITED(status) && WEXITSTATUS(status) != EX_OK)
			errx(EX_UNAVAILABLE, "preprocessor exited with status %d",
				WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			errx(EX_UNAVAILABLE, "preprocessor exited with signal %d",
				WTERMSIG(status));
	}
}

int
main(int ac, char *av[])
{
	ipfw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (ipfw_socket < 0)
		err(EX_UNAVAILABLE, "socket");

	memset(keywords, 0, sizeof(struct ipfw_keyword) * KEYWORD_SIZE);
	memset(mappings, 0, sizeof(struct ipfw_mapping) * MAPPING_SIZE);

	prepare_default_funcs();

	if (ac > 1 && av[ac - 1][0] == '/' && access(av[ac - 1], R_OK) == 0)
		ipfw_readfile(ac, av);
	else
		ipfw_main(ac, av);
	return EX_OK;
}

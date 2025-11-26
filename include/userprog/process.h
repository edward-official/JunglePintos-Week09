#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <stdbool.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include <list.h>

struct wait_status {
  struct list_elem elem;
  struct semaphore sema;
  struct lock lock;
  tid_t tid;
  int exit_code;
  int ref_cnt;
  bool exited;
};

struct fork_struct {
  struct thread *parent;
  struct intr_frame parent_if;
  struct semaphore semaphore;
  bool success;
  struct wait_status *wait_status;
};

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
void init_fds (struct thread *target);

#endif /* userprog/process.h */

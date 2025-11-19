#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stddef.h>
#include <stdbool.h>

struct thread;

void syscall_init (void);
int write_handler (int fd, const void *buffer, unsigned length);
void syscall_process_cleanup (void);
bool syscall_duplicate_fds (struct thread *parent, struct thread *child);

#endif /* userprog/syscall.h */

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stddef.h>

void syscall_init (void);
int write_handler (int fd, const void *buffer, unsigned length);
void syscall_process_cleanup (void);

#endif /* userprog/syscall.h */

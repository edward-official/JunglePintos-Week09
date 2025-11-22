#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init (void);

/*
extern를 선언하는 이유
extern를 선언하지 않으면 이 syscall.h파일을 사용하는 모든 프로그램의 공간에 filesys_lock이 할당이 되고 똑같은 이름의 락이 여러개 생성이 되기 때문에 프로그램이 사용할 때 에러가 납니다.
따라서 extern를 선언하여 할당하지 않고 나중에 선언하면 그것을 가져와서 쓰라고 애기해주는 것입니다. -> 링커가 하는 역할
*/
extern struct lock filesys_lock;

typedef int pid_t;

#endif /* userprog/syscall.h */

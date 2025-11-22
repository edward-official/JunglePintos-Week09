#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "lib/string.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *f);
void syscall_halt(struct intr_frame *f);
void syscall_exit(struct intr_frame *f);
void syscall_fork(struct intr_frame *f);
void syscall_exec(struct intr_frame *f);
void syscall_wait(struct intr_frame *f);
void syscall_create(struct intr_frame *f);
void syscall_remove(struct intr_frame *f);
void syscall_open(struct intr_frame *f);
void syscall_filesize(struct intr_frame *f);
void syscall_read(struct intr_frame *f);
void syscall_write(struct intr_frame *f);
void syscall_seek(struct intr_frame *f);
void syscall_tell(struct intr_frame *f);
void syscall_close(struct intr_frame *f);
void check_buf_address(struct intr_frame *f, char *buf, unsigned size);
void check_string_address(struct intr_frame *f, char *str_addr);

struct lock filesys_lock;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {

	lock_init(&filesys_lock);

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	int sys_case = f->R.rax;

	switch(sys_case){
		case SYS_HALT:
			power_off();
			break;
		case SYS_EXIT:
			syscall_exit(f);
			break;
		case SYS_FORK:
			syscall_fork(f);
			break;
		case SYS_EXEC:
			syscall_exec(f);
			break;
		case SYS_WAIT:
			syscall_wait(f);
			break;
		case SYS_CREATE:
			syscall_create(f);
			break;
		case SYS_REMOVE:
			syscall_remove(f);
			break;
		case SYS_OPEN:
			syscall_open(f);
			break;
		case SYS_FILESIZE:
			syscall_filesize(f);
			break;
		case SYS_READ:
			syscall_read(f);
			break;
		case SYS_WRITE:
			syscall_write(f);
			break;
		case SYS_SEEK:
			syscall_seek(f);
			break;
		case SYS_TELL:
			syscall_tell(f);
			break;
		case SYS_CLOSE:
			syscall_close(f);
			break;
	}
}

void syscall_exit(struct intr_frame *f){
	struct thread *curr = thread_current();
	int status = f->R.rdi;
	curr->exit_status = status;
	thread_exit();
}

void syscall_fork(struct intr_frame *f){
	char *name = f->R.rdi;

	check_string_address(f, name);

	tid_t return_fork = process_fork(name, f);
	if(return_fork == TID_ERROR){
		f->R.rax = TID_ERROR;
	}
	else{
		f->R.rax = return_fork;
	}
}

void syscall_exec(struct intr_frame *f){
	char *file = f->R.rdi;
	check_string_address(f, file);
	int result = process_exec(file);
	if(result == -1){
		f->R.rdi = -1;
		syscall_exit(f);
	}
}

void syscall_wait(struct intr_frame *f){
	pid_t pid = f->R.rdi;
	f->R.rax = process_wait(pid);
}

void syscall_create(struct intr_frame *f){
	char *file = f->R.rdi;
	unsigned initial_size = f->R.rsi;
	check_string_address(f, file);
	lock_acquire(&filesys_lock);
	f->R.rax = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
}

void syscall_remove(struct intr_frame *f){
	char *file = f->R.rdi;
	check_string_address(f, file);
	lock_acquire(&filesys_lock);
	f->R.rax = filesys_remove(file);
	lock_release(&filesys_lock);
}

void syscall_open(struct intr_frame *f){
	char *name = (char *)f->R.rdi;
	check_string_address(f, name);
	lock_acquire(&filesys_lock);
	struct file *open_file = filesys_open(name);
	lock_release(&filesys_lock);
	f->R.rax = -1;
	if(open_file == NULL){
		return;
	}
	else{
		for(int i=2; i<64; i++){
			if(thread_current()->fdt[i] == NULL){
				thread_current()->fdt[i] = open_file;
				f->R.rax = i;
				break;
			}
		}
	}
}

void syscall_filesize(struct intr_frame *f){
	int fd = f->R.rdi;
	if(fd>=2 && fd<64){
		lock_acquire(&filesys_lock);
		f->R.rax = file_length(thread_current()->fdt[fd]);
		lock_release(&filesys_lock);
	}
}

void syscall_read(struct intr_frame *f){
	int fd = f->R.rdi;
	void *buffer = f->R.rsi;
	unsigned size = f->R.rdx;
	struct thread *curr = thread_current();

	check_buf_address(f, buffer, size);

	if(fd == 0){
		for(unsigned i=0; i<size; i++){
			((char *)buffer)[i] = input_getc();
		}
		f->R.rax = size;
	}
	else if(fd >= 2 && fd < 64 && curr->fdt[fd] != NULL){
		struct file *file = curr->fdt[fd];

		lock_acquire(&filesys_lock);
		off_t byte = file_read(file, buffer, size);
		lock_release(&filesys_lock);

		f->R.rax = byte;
	}
	else{
		f->R.rax = -1;
	}

}

void syscall_write(struct intr_frame *f){
	int fd = f->R.rdi;
	char *buf = f->R.rsi;
	unsigned size = f->R.rdx;
	struct thread *curr = thread_current();

	check_buf_address(f, buf, size);
	
	lock_acquire(&filesys_lock);
	if(fd == 0){
		f->R.rax = -1;
	}
	else if(fd == 1) {
		putbuf(buf, size);
		f->R.rax = size;
	}
	else if(fd >= 2 && fd < 64 && curr->fdt[fd] != NULL){
		f->R.rax = file_write(curr->fdt[fd], buf, size);
	}
	else{
		f->R.rax = -1;
	}
	lock_release(&filesys_lock);
}

void syscall_seek(struct intr_frame *f){

	int fd = f->R.rdi;
	unsigned position = f->R.rsi;
	struct thread *curr = thread_current();

	if(curr->fdt != NULL){
		if(fd>=2 && fd<64){
			lock_acquire(&filesys_lock);
			file_seek(curr->fdt[fd], position);
			lock_release(&filesys_lock);
		}
	}
}

void syscall_tell(struct intr_frame *f){

	int fd = f->R.rdi;
	struct thread *curr = thread_current();

	if(curr->fdt != NULL){
		if(fd>=2 && fd<64){
			lock_acquire(&filesys_lock);
			f->R.rax = file_tell(curr->fdt[fd]);
			lock_release(&filesys_lock);
		}
	}
}

void syscall_close(struct intr_frame *f){

	int fd = f->R.rdi;
	struct thread *curr = thread_current();

	if(2<=fd && fd<64){

		struct file *close_file = curr->fdt[fd];

		if(close_file != NULL){
			lock_acquire(&filesys_lock);
			file_close(close_file);
			lock_release(&filesys_lock);
			curr->fdt[fd] = NULL;
			f->R.rax = 0;
		}
		else{
			f->R.rax = -1;
		}

	}
	else{
		f->R.rax = -1;
	}

}

void check_buf_address(struct intr_frame *f, char *buf, unsigned size){

	char *end = buf + size;

	if(buf == NULL){
		f->R.rdi = -1;
		syscall_exit(f);
	}

	while(buf < end){
		if(!is_user_vaddr(buf) || pml4_get_page(thread_current()->pml4, buf) == NULL){
			f->R.rdi = -1;
			syscall_exit(f);
		}

		buf = (char *)pg_round_down(buf) + 4096;
	}
}

void check_string_address(struct intr_frame *f, char *str_addr){

	if(str_addr == NULL){
		f->R.rdi = -1;
		syscall_exit(f);
	}

	while(true){
		if(!is_user_vaddr(str_addr) || pml4_get_page(thread_current()->pml4, str_addr) == NULL){
			f->R.rdi = -1;
			syscall_exit(f);
		}
		if(str_addr[0] == '\0'){
			break;
		}
		str_addr += 1;
	}

}
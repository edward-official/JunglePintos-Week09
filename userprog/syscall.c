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

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
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
			
			break;
		case SYS_TELL:
			
			break;
		case SYS_CLOSE:
			syscall_close(f);
			break;
	}
}

void syscall_exit(struct intr_frame *f){
	int status = f->R.rdi;
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

void syscall_fork(struct intr_frame *f){
	char *name = f->R.rdi;

	check_address(f, name);

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
	check_address(f, file);
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
	check_address(f, file);
	f->R.rax = filesys_create(file, initial_size);
}

void syscall_open(struct intr_frame *f){
	char *name = (char *)f->R.rdi;
	check_address(f, name);
	struct file *open_file = filesys_open (name);
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
	f->R.rax = file_length(thread_current()->fdt[fd]);
}

void syscall_read(struct intr_frame *f){
	int fd = f->R.rdi;
	void *buffer = f->R.rsi;
	unsigned size = f->R.rdx;
	struct thread *curr = thread_current();

	check_address(f, buffer);

	if(fd == 0){
		for(unsigned i=0; i<size; i++){
			((char *)buffer)[i] = input_getc();
		}
		f->R.rax = size;
	}
	else if(fd >= 2 && fd < 64 && curr->fdt[fd] != NULL){
		struct file *file = curr->fdt[fd];

		off_t byte = file_read(file, buffer, size);

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

	check_address(f, buf);
	
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
}

void syscall_close(struct intr_frame *f){

	int fd = f->R.rdi;
	struct thread *curr = thread_current();

	if(2<=fd && fd<64){

		struct file *close_file = curr->fdt[fd];

		if(close_file != NULL){
			file_close(close_file);
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

void check_address(struct intr_frame *f, char *buf){
	if(buf == NULL || !is_user_vaddr(buf)){
		f->R.rdi = -1;
		syscall_exit(f);
	}
	if(pml4_get_page(thread_current()->pml4, buf) == NULL){
		f->R.rdi = -1;
		syscall_exit(f);
	}
}
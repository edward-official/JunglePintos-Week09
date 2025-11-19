#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "include/lib/string.h"
#include "threads/synch.h"
#include "devices/timer.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	char *save_ptr;
	char *name_ptr = palloc_get_page(0);
	if(name_ptr == NULL){
		palloc_free_page(fn_copy);
		return TID_ERROR; 
	}
	strlcpy(name_ptr, file_name, PGSIZE);
	char *thread_name = strtok_r(name_ptr, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (thread_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

struct fork_aux{
	struct thread *parent;
	struct intr_frame *if_;
	struct semaphore *fork_sema;
};

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_) {
	struct fork_aux aux;
	struct semaphore fork_sema;

	sema_init(&fork_sema, 0);

	aux.parent = thread_current();
	aux.if_ = if_;
	aux.fork_sema = &fork_sema;

	tid_t tid = thread_create (name, PRI_DEFAULT, __do_fork, &aux); 
	if(tid == TID_ERROR){
		return TID_ERROR;
	}

	sema_down(&fork_sema);

	return tid;
}

#ifndef VM
/*
	이 함수를 pml4_for_each에 전달하여 부모의 주소 공간을 복제합니다.
	이것은 프로젝트 2만을 위한 것입니다. 
*/
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: 만약 부모 페이지가 커널 페이지라면, 즉시 리턴(종료)합니다. */
	if(is_kernel_vaddr(va)){
		return true;
	}

	/* 2. 부모의 PML4(페이지 맵 레벨 4)에서 VA(가상 주소)를 해석하여 실제 주소를 찾습니다. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 
		3. TODO: 자식을 위해 새로운 PAL_USER 페이지를 할당하고,
		그 결과를 NEWPAGE에 저장합니다. 
	*/
	newpage = palloc_get_page(PAL_USER);
	if(newpage == NULL){
		return false;
	}
	memcpy(newpage, parent_page, PGSIZE);

	/* 
		4. TODO: 부모의 페이지를 새 페이지로 복제하고,
		부모의 페이지가 쓰기 가능한지 확인합니다 (그 결과에 따라
		WRITABLE 변수를 설정하세요). 
	*/

	writable = is_writable(pte);

	/* 
		5. WRITABLE 권한을 설정하여 자식의 페이지 테이블의
		VA 주소에 새 페이지를 추가합니다. 
	 */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: 페이지 삽입에 실패했다면, 에러 처리를 수행합니다. */
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

/*
	부모의 실행 컨텍스트를 복사하는 스레드 함수입니다.
	힌트) parent->tf (부모 스레드 구조체)는 프로세스의 유저랜드 컨텍스트를 가지고 있지 않습니다.
	즉, 여러분은 process_fork()의 두번째 인자(intr_frame)을 이 함수로 전달해야 합니다.
*/
static void
__do_fork (void *aux) {

	struct fork_aux *args = aux;

	struct intr_frame if_;
	struct thread *parent = args->parent;
	struct thread *current = thread_current ();
	/* TODO: 어떻게든 parent_if(즉, process_fork() 함수의 if_)를 전달해야 합니다. */
	struct intr_frame *parent_if;
	bool succ = true;

	/* 1. CPU 컨텍스트를 로컬 스택으로 읽어옵니다. */
	parent_if = args->if_;
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	if_.R.rax = 0;

	/* 2. 페이지 테이블을 복제합니다. */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/*
	TODO: 여기에 여러분의 코드를 작성하세요.
	힌트) 파일 객체를 복제하려면 include/filesys/file.h에 있는 file_duplicate 함수를 사용하세요.
	(중요) 부모는 자식 프로세스가 부모의 자원을 성공적으로 복제할 때까지 fork()에서 반환해서는 안됩니다.
	*/

	for(int i=2; i<64; i++){
		if(parent->fdt[i] != NULL){
			current->fdt[i] = file_duplicate(parent->fdt[i]);
		}
	}

	process_init ();

	struct semaphore *fork_sema = args->fork_sema;
	if(fork_sema != NULL) sema_up(fork_sema);

	/* 마지막으로, 새롭게 만든 프로세스로 스위칭 */
	if (succ)
		do_iret (&if_);
error:
	if(fork_sema != NULL) sema_up(fork_sema);
	thread_exit ();
}

// NOTE : exec함수
/* 현재 실행 중인 스레드의 코드와 메모리를 싹 비우고, 새로운 프로그램으로 갈아치운 뒤 실행하는 함수 */

int process_exec (void *f_name) {
	//인자로 받은 파일 이름의 주소(예 : "ls -l foo")
	char *file_name = palloc_get_page(PAL_ZERO);
	if(file_name == NULL) return -1;
	strlcpy(file_name, f_name, PGSIZE);

	bool success;

	//CPU 레지스터 상태를 담을 구조체
	//커널모드에서 유저모드로 점프하고 난 뒤 사용할 레지스터 값들을 세팅
	struct intr_frame _if;
	//SEL_UDSEG / SEL_UCSEG -> 유저 데이터 영역, 유저 코드 영역을 사용한다.
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	//인터럽트 허용 -> 프로그램 실행 중에 타이머나 키보드 입력을 받을 수 있게 인터럽트를 켭니다.
	_if.eflags = FLAG_IF | FLAG_MBS;

	//현재 프로세스가 가지고 있던 메모리(페이지 테이블, 파일 등)를 싹 지웁니다.
	//새로운 프로그램으로 덮어쓰는 것이 목표기 때문에, 이전에 쓰던 흔적을 지우는 것.
	process_cleanup ();

	//하드디스크에서 file_name에 해당하는 파일(ELF)을 읽습니다.
	//메모리에 코드와 데이터를 복사합니다.
	//스택에 인자를 쌓습니다.(Argument Passing)
	//_if 채우기 : _if.rip -> 프로그램 시작점 주소를 넣습니다.
	//			  _if.rsp -> 아까 인자를 쌓은 스택의 꼭대기 주소를 넣습니다.
	success = load (file_name, &_if);

	//파일 이름 문자열은 이제 필요 없으니 메모리 해제
	palloc_free_page (file_name);
	//load가 실패하면 -1 리턴(프로세스 종료)
	if (!success)
		return -1;

	//열심히 설정한 _if구조체의 내용을 실제 CPU 레지스터에 쏜다.
	//이 명령어가 실행되는 순간, _if.rip이 가르키는 함수로 점프
	//동시에 권한 레벨이 Kernel Mode -> User Mode로 바뀐다.
	do_iret (&_if);
	//정상적이면 실행되지 않을 코드. -> do_iret으로 유저 세상으로 떠나기 때문
	//만약 실행되면 잘못된것. 커널 패닉
	NOT_REACHED ();
}


/* 
	스레드 TID가 종료될 때까지 기다리고 그 종료 상태를 반환합니다.
	만약 커널에 의해 종료되었다면 (예: 예외 상황으로 인해 강제 종료됨),
	-1을 반환합니다. TID가 유효하지 않거나, 호출 프로세스의 자식이 아니거나,
	또는 해당 TID에 대해 process_wait()이 이미 성공적으로 호출되었다면,
	기다리지 않고 즉시 -1을 반환합니다.
*/
//NOTE : wait 함수 -> 세마포어를 구현하라.
int
process_wait (tid_t child_tid) {

	struct thread *curr = thread_current();

	if(!list_empty(&curr->child_list)){
		for(struct list_elem *i=list_front(&curr->child_list); i!=list_end(&curr->child_list); i = list_next(i)){
			struct thread *temp_thread = list_entry(i, struct thread, elem_for_parent);
			if(temp_thread->tid == child_tid){
				sema_down(&temp_thread->child_sema);
				list_remove(&temp_thread->elem_for_parent);
				return temp_thread->exit_status;
			}
		}
	}


	return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();

	if(curr->fdt != NULL){
		for(int i=2; i<64; i++){
			if(curr->fdt[i] != NULL){
				file_close(curr->fdt[i]);
				curr->fdt[i] = NULL;
			}
		}
		
		palloc_free_page(thread_current()->fdt);
	}

	sema_up(&curr->child_sema);

	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);


// NOTE : load함수
//하드디스크에서 file_name에 해당하는 파일(ELF)을 읽습니다.
//메모리에 코드와 데이터를 복사합니다.
//스택에 인자를 쌓습니다.(Argument Passing)
//_if 채우기 : _if.rip -> 프로그램 시작점 주소를 넣습니다.
//			  _if.rsp -> 아까 인자를 쌓은 스택의 꼭대기 주소를 넣습니다.
static bool load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;
	
	//file_name을 자르기 위한 변수
	char *fn_copy = palloc_get_page(0);
	char *token;
	char *save_ptr;
	char *argv[64];
	int argc = 0;

	strlcpy(fn_copy, file_name, PGSIZE);
	token = strtok_r(fn_copy, " ", &save_ptr);
	argv[0] = token;
	argc++;
	while(token != NULL){
		//NULL로 설정하면 이전에 읽던 부분부터 읽음.
		token = strtok_r(NULL, " ", &save_ptr);
		if(token != NULL){
			argv[argc] = token;
			argc++;
		}
	}

	//페이지 테이블 생성
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL) goto done;
	//CR3 레지스터 교체 -> CPU는 이 페이지 테이블을 써라.
	process_activate (thread_current ());

	//디스크에서 file_name이라는 파일을 찾아서 열음.
	//NOTE : 수정 -> file_name을 그대로 넣으면 "ls -l foo"를 찾는게 되어버림.
	file = filesys_open (argv[0]);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	//ELF 헤더 검사 -> 파일의 맨 앞부분을 size ehdr만큼 읽어서 검사.
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	//헤더 목차 읽기 -> 세그먼트들의 구역을 알 수 있다. ex) 코드 0x400000, 데이터 0x600400, BSS 0x600600
	//목차 시작 위치
	file_ofs = ehdr.e_phoff;
	//목차 갯수 만큼 반복
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		//목차 위치로 이동
		file_seek (file, file_ofs);

		//목차 내용 읽기
		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		//세그먼트 타입 검사
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			//실제 코드나 변수니까 메모리에 올려달라.
			case PT_LOAD:
				//이 파일이 문제가 없나 검사 하는 것 -> 유저 영역에 위치하고 있나?, NULL포인터냐?, 크기 검사.
				if (validate_segment (&phdr, file)) {
					//쓰기 권한 확인
					bool writable = (phdr.p_flags & PF_W) != 0;
					//~PGMASK로 하면 하위 12비트가 0으로 정렬됨 -> 주소 정렬
					//파일 내에서 시작 페이지
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					//메모리 내에서 시작 페이지
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					//페이지 내에서 데이터가 시작하는 오프셋
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					//디스트에서 읽어올 데이터 크기와 디스크엔 없지만 메모리에 0으로 채워야할 공간 크기
					uint32_t read_bytes, zero_bytes;

					if (phdr.p_filesz > 0) {
						//읽을 바이트와 0으로 채울 바이트를 계산
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						//파일엔 없지만 메모리엔 필요한 경우 -> 전역변수 초기화
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					//메모리에 매핑하는 과정 load_segment -> palloc으로 메모리 할당, file_read로 데이터를 읽고 채우고, memset으로 나머지 채우고 installpage로 페이지테이블에 매핑
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	//유저 스택에 스택을 생성
	if (!setup_stack (if_))
		goto done;

	//가장 처음 실행할 명령어의 주소를 설정
	if_->rip = ehdr.e_entry;

	//여기에 if_->R->rsi 이런걸 채워야 한다는건가?
	if_->R.rdi = argc;

	//진짜 argument 데이터를 집어 넣어줌. rsp는 USER_STACK으로 이미 초기화 되어있음.
	for(int i = argc-1; i>=0; i--){
		if_->rsp -= strlen(argv[i])+1;
		memcpy(if_->rsp, argv[i], strlen(argv[i])+1);
		argv[i] = (char *)if_->rsp;
	}

	//8바이트의 배수로 패딩
	while(if_->rsp % 8 != 0){
		if_->rsp -= 1;
		*(uint8_t *)if_->rsp = 0;
	}

	//argument주소를 넣어주기 전에 주소0값 추가
	if_->rsp -= 8;
	*(char **)if_->rsp = 0;

	//argument주소 차례대로 추가
	for(int i = argc-1; i>=0; i--){
		if_->rsp -= 8;
		*(char **)if_->rsp = argv[i];
	}

	//반송 주소 0을 넣기전 rsi레지스터 설정
	if_->R.rsi = if_->rsp;

	//반송 주소 0 넣어주고 끝
	if_->rsp -= 8;
	*(void **)if_->rsp = 0;


	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);

	//NOTE : 추가
	//fn_copy를 다 썼으므로 free시켜줌.
	palloc_free_page(fn_copy);

	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */

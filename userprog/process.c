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
//#include "include/lib/string.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif


static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
struct thread *get_child_process(tid_t child_tid);
static void __do_fork (void *);

/*그룹 1: 핵심 프로세스 관리 (생명주기 관리)
프로세스의 상태를 바꾸고, 자원을 할당/해제하는 기본적인 관리 작업을 수행
process_init, process_activate, process_cleanup, process_exit, process_wait 등*/

/*그룹 2: 프로세스 생성과 실행 (프로그램 로딩)
특정 실행 파일을 읽어 새로운 프로세스로 탄생시키는 과정
process_create_initd & initd, process_exec, load, setup_stack, load_segment, install_page, valide_segement*/

/*그룹 3: 프로세스 복제 ('fork')
현재 프로세스와 거의 동일한 복제본을 만드는 fork 시스템 콜을 위한 것
process_fork, __do_fork, duplicate_pte*/


/*
역할: 프로세스 관련 자료구조를 초기화.
동작: 현재 스레드(thread_current())의 프로세스 관련 정보를 초기화한다.
*/
static void
process_init (void) {
	struct thread *current = thread_current ();



	current->fd_table = palloc_get_page(PAL_ZERO);
	if(current->fd_table == NULL)
		return;

}

/* 
역할: Pintos의 최초 사용자 프로세스 ("initd")를 생성.
동작: process_create_initd는 initd라는 커널 스레드를 만든다. initd는 실행되자마자 
process_exec을 호출하여 자기 자신을 첫 번째 사용자 프로세스로 변신시킨다. 
*/
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;			//file_name의 복사본을 저장할 포인터
	tid_t tid;				//새로 생성될 쓰레드의 ID (프로세스 ID의 역할)

	

	/* FILE_NAME을 복사하는 이유
	file_name은 이 함수를 호출한 곳(caller)의 메모리 공간에 있을 수 있음.
	thread_create()는 새 스레드를 만들고, 그 스레드는 나중에 load() 함수를 호출하여 file_name을 사용한다.
	만약 caller가 file_name을 load()가 사용하기 전에 변경하거나 해제하면 문제가 발생(race condition)
	이를 방지하기 위해 안전하게 커널 메모리에 복사본을 만든다. */

	//동작: 커널 메모리에서 4kb (한 페이지)를 할당받고 file_name의 문자열 복사본을 저장한다. '0'플래그는 페이지를 0으로 초기화하지 않겠다는 의미.
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	//file_name 문자열을 fn_copy 공간으로 안전하게 복사한다.
		strlcpy (fn_copy, file_name, PGSIZE);

	
	/* file_name을 실행할 새 스레드를 생성한다. */

	/*동작: 새로운 커널 스레드를 생성한다.
	thread_create(쓰레드 이름, 쓰레드 기본 우선순위, 새로 생성된 쓰레드가 실행할 함수, 함수에게 전달될 인자)*/
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}
/* tid를 이용해 현재 프로세스의 자식 리스트에서 해당 자식 스레드를 찾는 함수 */
struct thread *get_child_process(tid_t child_tid) {
    struct thread *parent = thread_current();
    struct list *children = &parent->children;

    /* 자식 리스트를 순회하며 tid가 일치하는 자식을 찾는다. */
    for (struct list_elem *e = list_begin(children); e != list_end(children); e = list_next(e)) {
        struct thread *child = list_entry(e, struct thread, child_elem);
        if (child->tid == child_tid) {
            return child; /* 자식을 찾으면 해당 스레드 포인터를 반환한다. */
        }
    }
    /* 리스트를 모두 찾아도 없으면 NULL을 반환한다. */
    return NULL;
}

/* 첫 번째 사용자 프로세스를 실행시키는 스레드 함수 */
static void
initd (void *f_name) { //f_name은 process_create_initd에서 전달받은 프로그램 이름 문자열 포인터
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif
	//이 부분은 가상 메모리에서 사용, 보조 페이지 테이블(spt)을 초기화하는 코드

	//현재 스레드의 프로세스(이제 곧 프로세스가 될) 관련 정보를 초기화
	process_init ();

	/*process_exec(f_name): f_name에 해당하는 프로그램을 현재 실행중인 'init'스레드 위로 덮어씌우는(load) 작업 시도
	성공시: process_exec 함수는 성공하면 절대 리턴하지 않음. 대신 do_iret()을 통해 사용자 프로그램의 첫 코드부터 실행 시작,
	따라서 if문 안으로 돌아오지 않는다.
	실패시: process_exec가 -1을 반환하는 경우. 최초의 프로세스를 띄우는데 실패한 것은 운영체제 입장에서
	치명적인 오류이므로, PANIC 매크로를 호출하여 시스템 전체를 중단.*/
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* fork를 위한 정보 전달용 구조체 */
struct fork_aux {
	struct thread *parent;
	struct intr_frame *if_;
	struct semaphore *fork_sema;
};

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	struct fork_aux aux;
	struct semaphore fork_sema;
	tid_t tid;

	/* 1. 부모와 자식 간의 동기화를 위한 일회용 세마포어를 초기화한다. */
	sema_init(&fork_sema, 0);

	/* 2. 자식에게 전달할 정보(부모, 인터럽트 프레임, 세마포어 주소)를 설정한다. */
	aux.parent = thread_current();
	aux.if_ = if_;
	aux.fork_sema = &fork_sema;

	/* 3. 자식 스레드를 생성하고 정보 꾸러미(aux)를 전달한다. */
	tid = thread_create (name, PRI_DEFAULT, __do_fork, &aux);
	if (tid == TID_ERROR)
		return TID_ERROR;

	/* 4. 자식이 준비를 마칠 때까지(sema_up 호출) 기다립니다. */
	sema_down(&fork_sema);

	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux; // __do_fork에서 전달된 부모 스레드
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. 가상 주소(va)가 커널 영역 주소이면 복제하지 않고 즉시 반환한다.
	 *    자식 프로세스는 부모의 유저 공간만 복제해야 한다. */
	if (is_kernel_vaddr(va)) {
		return true;
	}

	/* 2. Resolve VA from the parent's page map level 4. */
	/*    부모의 페이지 테이블에서 가상 주소(va)에 매핑된 물리 페이지 주소를 찾는다. */
	parent_page = pml4_get_page (parent->pml4, va);
	if (parent_page == NULL) {
		/* 부모에게 매핑되지 않은 페이지는 복제할 필요가 없다. */
		return true;
	}

	/* 3. 자식 프로세스를 위해 새로운 물리 페이지를 할당받는다. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL) {
		/* 메모리 할당에 실패하면 복제를 중단하고 false를 반환한다. */
		return false;
	}

	/* 4. 부모 페이지의 내용을 자식을 위해 할당받은 새 페이지로 복사한다. */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte); // 부모 페이지의 쓰기 가능 여부를 확인한다.

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	/*    자식의 페이지 테이블에 가상주소(va)와 새 물리페이지(newpage)를 매핑한다. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. 페이지 매핑에 실패하면 할당받았던 페이지를 해제하고 false를 반환한다. */
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct fork_aux *args = aux;
	struct intr_frame if_;
	struct thread *parent = args->parent;
	struct thread *current = thread_current (); // 현재 실행 중인 자식 스레드.
	/* 부모가 시스템 콜을 호출한 시점의 유저 컨텍스트를 가져온다. */
	struct intr_frame *parent_if = args->if_;
	bool succ = true;

	/* 자식 프로세스의 파일 디스크립터 테이블을 할당합니다. */
	current->fd_table = palloc_get_page(PAL_ZERO);
	if (current->fd_table == NULL) {
		goto error;
	}

	/* 1. Read the cpu context to local stack. */
	/* 1. 부모의 CPU 문맥(레지스터 값)을 자식의 스택으로 복사한다. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	/* 자식 프로세스에서 fork의 반환 값은 0이어야 한다.
	 * rax 레지스터는 함수의 반환 값을 저장하는 데 사용된다. */
	if_.R.rax = 0;

	/* 2. 페이지 테이블(메모리 공간)을 복제합니다. */
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

	/* 3. 부모의 파일 디스크립터 테이블을 복제한다. */
	// 표준 입출력(0, 1)을 제외한 파일들을 복제한다.
	for (int i = 2; i < FDT_COUNT_LIMIT; i++) {
		struct file *file = parent->fd_table[i];
		if (file != NULL) {
			// file_duplicate는 동일한 파일을 가리키는 새 파일 객체를 만든다.
			// 파일 오프셋 등은 공유하지만, 파일 디스크립터는 독립적이다.
			current->fd_table[i] = file_duplicate(file);
		}
	}
	current->next_fd = parent->next_fd;

	/* 4. 부모-자식 관계를 설정하고, fork 완료 신호를 보낸다. */
	/* 부모가 전달해준 일회용 세마포어에 신호를 보내 깨워준다. */
	sema_up(args->fork_sema);

/* 5. 모든 복제가 성공했으면, 사용자 모드로 전환하여 자식 프로세스 실행을 시작한다. */
	if (succ)
		do_iret (&if_);

error:
	current->exit_status = TID_ERROR; // 실패 시 종료 상태 설정
	/* 복제 과정에서 오류 발생 시, 부모에게 실패를 알리고 스레드를 종료한다. */
	sema_up(args->fork_sema); // 실패했더라도 부모를 깨워야 한다.
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success; 

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	success = load (file_name, &_if);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
		return -1;

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
	 * immediately, without waiting. 
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) { /*
process_wait (tid_t child_tid) {
	/* 1. 자식 리스트에서 child_tid에 해당하는 자식 스레드를 찾습니다. */
	struct thread *child = get_child_process(child_tid);

	/* 자식을 찾지 못했거나, 이미 wait한 자식인 경우 -1을 반환합니다. */
	if (child == NULL) {
		return -1;
	}

	/* 2. 자식의 개인 세마포어(wait_sema)를 사용하여 자식이 종료될 때까지 기다립니다. */
	sema_down(&child->wait_sema);

	/* 3. 자식이 남긴 종료 상태를 가져오고, 부모의 자식 리스트에서 제거합니다. */
	int exit_status = child->exit_status;
	list_remove(&child->child_elem);

	/* 4. 자식의 종료 상태를 반환합니다. */
	return exit_status;
}


/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	/* 자신을 기다리는 부모가 있다면, 자신의 개인 세마포어(wait_sema)를 up하여 깨워줍니다. */
	sema_up(&curr->wait_sema);
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

/* 모든 컨텍스트 스위치시 호출되는 함수.
다음에 실행될 스레드에서 사용자 코드를 실행하기 위해 CPU를 설정한다. */
void
process_activate (struct thread *next) {
	/* 스레드의 페이지 테이블을 활성화한다.
	1. pm14: 각 프로세스는 자신만의 독립적인 가상 메모리 주소 공간을 가진다.
	pm14는 이 가상 주소를 실제 물리 주소로 변환하는 '주소 변환표'의 최상의 테이블이다.
	즉 프로세스 A와 프로세스 V는 같은 가상 주소 0x400000을 사용하더라도,
	각자의 pm14를 통해 서로 다른 물리 메모리 위치에 연결된다.
	2. pm14_activate(): CPU의 CR3라는 특별한 제어 레지스터에 next 프로세스의 pm14 주소를 등록하는 역할
	3. 결과: 이 함수가 실행된 직후부터, CPU는 메모리에 접근할 때 next 프로세스의 주소 변환표(pm14)를 사용한다.
	이로써 프로세스간의 메모리 공간이 완벽하게 격리된다. */
	pml4_activate (next->pml4);
	
	/*어떤 프로세스가 실행 중이든, 인터럽트가 발생하면 CPU는 항상 현재 실행중인 프로세스에 할당된 안전한 커널 스택으로 자동 전환한다. */
	tss_update (next);
}

/* WLD 실행 파일의 구조를 해석하기 위한 상수들.
Pintos가 사용자 프로그램을 메모리에 올리고 실행하려면 그 프로그램 파일이 어떤 형식으로 되어있는지 알아야 하는데,
ELF가 바로 그 표준 형식이다. */
#define EI_NIDENT 16


/*프로그램 헤더: ELF 파일에는 "프로그램 헤더 테이블"이라는 것이 있다. 이 테이블의 각 항목(엔트리)은 실행 파일의
특정 세그먼트에 대한 정보를 담고 있다. 세그먼트는 코드, 데이터, 스택 등 메모리에 로드될 수 있는 프로그램의 논리적인 부분을 의미한다. */

/*각 프로그램 헤더는 p_type이라는 필드를 가지며, 이 필드가 해당 세그먼트의 종류를 나타낸다.*/
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* 실행 */
#define PF_W 2          /* 쓰기 */
#define PF_R 4          /* 읽기 */

/* ELF 파일 식별 정보 (16바이트)
파일의 맨 앞 16바이트를 읽어 이 배열에 저장한다.
배열의 첫 바이트가 매직 넘버("\177ELF")와 일치하는지 확인하여
이 파일이 유효한 ELF 파일인지 가장 먼저 검사하고 64비트용 파일인지 등의 정보도 담겨있다 */
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

/* 실행 파일의 설계도(ELF)를 읽어 메모리에 실제로 배치하는 과정 */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();   //현재 실행중인 스레드(프로세스)의 정보
	struct ELF ehdr;						//ELF 헤더 정보를 담을 구조체
	struct file *file = NULL;				//실행 파일을 가리킬 파일 포인터
	off_t file_ofs;							//파일 내에서 읽을 위치(오프셋).
	bool success = false;					//로딩 성공 여부 플래그
	int i;

	/*파싱을 위한 변수 선언*/
	char line_copy[128];
    char *token;
    char *save_ptr;
    char *argv[64];	//왜 64로 선언할까?
    int argc = 0;

	strlcpy(line_copy, file_name, sizeof(line_copy));
	for(token = strtok_r(line_copy, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)){
		argv[argc] = token;
		argc ++;
	}

	if(argc > 0){
		strlcpy(thread_current()->name, argv[0], sizeof(thread_current()->name));
	}

	/* 페이지 디렉토리(페이지 테이블)를 할당하고 활성화한다.
	이것이 새 프로세스를 위한 독립적인 메모리 지도가 된다. */

	//새 프로세스를 위한 최상위 페이지 테이블(pml4)을 생성한다. 지금은 아무것도 없는 빈 지도 상태.
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL){
		printf("DEBUG: pml4_create() failed\n"); // [추가]
    	goto done;
	}
	//방금 만든 빈 지도를 CPU에게 사용하라고 알려준다. 이제부터 모든 메모리 접근은 이 새 지도를 통한다. 
	process_activate (thread_current ());

	/* 파일 시스템을 통해 file_name에 해당하는 파일을 연다. */ 
	file = filesys_open (argv[0]);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		printf("DEBUG: filesys_open() failed\n"); // [추가]
		goto done;
	}

	/* 실행 파일의 헤더를 읽고 유효한지 검증하는, 파일의 "설계도"가 올바른 형식인지 확인하는 과정이다. */
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

	/* 프로그램 헤더들을 읽는다. 설계도(ELF 헤더)를 바탕으로, 각 부분(세그먼트)에 대한 상세 정보를 하나씩 확인하는 과정이다. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}
	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;
	
/*
 (높은 주소)
+--------------------------------+ <-- USER_STACK (예: 0x8000000000)
|                                |
|         "x\0"                  |
|         "echo\0"               |  (1. 실제 문자열 데이터)
|                                |
+--------------------------------+
|         0 (Padding)            |  (2. 정렬 패딩)
+--------------------------------+
|         NULL (argv[argc])      |  (3. NULL 포인터)
+--------------------------------+
|  "x"의 주소 (argv[argc-1])     |
|         ...                   |
|  "echo"의 주소 (argv[0])       |  (4. argv 주소들)
+--------------------------------+ <-- if_->R.rsi 가 가리키는 곳 (argv 배열의 시작)
|  0 (가짜 반환 주소)            |  (5. 가짜 반환 주소)
+--------------------------------+ <-- 최종 if_->rsp 가 가리키는 곳
*/
	void *user_stack_addrs[64];

	//스택에 데이터 넣기 1단계: 실제 문자열 데이터(ex: "echo", "x") 넣기
	for(int i = argc-1; i>=0; i--){
		int len = strlen(argv[i]) + 1;
		if_->rsp -= len; 		//NULL만큼 1을 더해준다.
		memcpy((void *)if_->rsp, argv[i], strlen(argv[i])+1);	//argv[i] 전체가 가리키는 문자열을 rsp로 len만큼 복사
		user_stack_addrs[i] = (void *)if_->rsp;
	}
	
	//스택에 데이터 넣기 2단계: 워드 정렬 맞추기(패딩).
	while(if_->rsp % 8 != 0){
		if_-> rsp -= 1;
		*(uint8_t *)if_ -> rsp = 0;
	}

	//스택에 데이터 넣기 3단계: NULL 넣기
	if_->rsp -= 8;
	*(char **)if_->rsp = 0;

	//스택에 데이터 넣기 4단계: argv 주소 저장.
	for(int i = argc-1; i>=0; i--){
		if_->rsp -= 8;
		*(void **)if_->rsp = user_stack_addrs[i];
	}

	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp;

	if_->rsp -= 8;

	//스택에 데이터 넣기 5단계: 가짜 반환값 저장.
	*(void **)if_->rsp = 0;

	/* Start address. */
	if_->rip = ehdr.e_entry;
	
	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	return success;
}


/* ELF 파일에 명시된 특정 세그먼트 정보가 안전하고 유효한지 검증하는 방어 코드 */
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

 /*
 load 함수로부터 "어떤 파일의 어느 위치에서 얼마만큼의 데이터를 읽어 어떤 가상 주소에 어떤 권한으로 올려라"는 지시를 받는다.
 struct file *file: 데이터를 읽어올 실행 파일 포인터.
 off_t ofs: file 내에서 데이터를 읽기 시작할 위치(오프셋).
 uint8_t *upage: 데이터를 올리기 시작할 사용자 가상 주소.
 uint32_t read_bytes: file로부터 읽어야 할 총 데이터의 크기.
 uint32_t zero_bytes: read_bytes를 다 읽은 후 0으로 채워야 할 데이터의 크기
 bool writable: 이 메모리 영역에 쓰기 권한을 부여할 지 여부
 */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	/*
	1. read_bytes + zero_bytes(세그먼트의 총 메모리 크기)가 페이지(PGSIZE, 4KB) 크기의 배수여야 한다.
	2. upage(사용자 가상 주소)가 페이지 경계에 정확히 맞춰져 있어야 한다.
	3. ofs(파일 오프셋)도 페이지 경계에 맞춰져 있어야 로딩이 단순해진다.
	*/
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	//file에서 데이터를 읽기 시작할 위치(ofs)로 파일 포인터를 이동
	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* 아직 파일에서 읽을 내용이 있거나 0으로 채울 부분이 남았다면 계속 while 루프를 실행한다. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* 데이터를 담을 실제 물리 메모리 한 페이지를 커널로부터 할당. 실패(메모리 부족)하면 false를 반환.
		kpage는 이 물리 페이지를 가리키는 커널 주소이다. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);
		
		/* install_page 함수를 호출하여, 사용자 가상 주소(upage)와 실제 데이터가 담긴 물리 페이지(kpage)를 
		페이지 테이블에 기록하여 연결한다. 이로써 프로세스가 upage 주소에 접근하면 실제로는 kpage에 접근한다.
		writable 권한도 이 때 설정된다. */
		if (!install_page (upage, kpage, writable)) {
		
			palloc_free_page (kpage);
			return false;
		}

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

/* 앞서 load_segment가 물리 페이지에 데이터 채우기까지 했다면, 가상 주소를 부여하고 등록하는 역할
*upage: 사용자 프로그램이 사용할 가상 주소(예: 0x4001000).
*kpage: 실제 데이터가 저장된 물리 페이지를 가리키는 커널 주소 (palloc_get_page로 할당받은 그 주소).
*bool writable: 이 페이지에 쓰기를 허용할지 아니면 읽기만 허용할지 권한 정보. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* 해당 가상 주소에 이미 매핑된 페이지가 없는지 확인하고,
	우리의 페이지을 그 곳에 매핑 */
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

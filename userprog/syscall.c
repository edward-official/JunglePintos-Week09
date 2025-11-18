#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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


/*'syscall_init(void)
	*역할: 시스템 콜 메커니즘을 단 한번 초기화함
	*동작: Pintos가 부팅될 때 호출된다. 이 함수는 CPU에게 "앞으로 int0x30이라는 인터럽트가 발생하면,
	무조건 syscall_handler 함수를 실행시켜라"고 등록하는 역할을 한다. 사용자 프로그램의 모든 시스템 콜 함수
	(C 라이브러리의 write, exec 등)는 내부적으로 int $0x30 명령어를 실행하도록 만들어졌다.*/
void
syscall_init (void) {
	//시스템 콜이 발생하고 끝날 때, 어떤 권한으로 전환할지 CPU에게 알려주는 규칙 설정 단계
	//((uint64_t)SEL_UCSEG - 0x10) << 48: 커널에서 SYSRET으로 복귀할 때는 사용자모드(특권 레벨 3)로 전환하고 코드는 사용자 코드 세그먼트(SEL_UCSEG)소속으로 실행
	//((uint64_t)SEL_KCSEG) << 32: 사용자모드에서 SYSCALL을 호출하면 커널 모드(특권 레벨 0)로 전환하고, 코드는 커널 코드 세그먼트(SEL_KCSEG)소속으로 실행
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);

	//SYSCALL이 호출될 때, 어디로 점프해서 코드를 실행 시작할지 CPU에게 알려주는 "목적지 주소 설정" 단계이다.
	//MSR_LSTAR: Long-mode System call Target Address Register의 약자. 이름 그대로 시스템 콜의 목적지 주소를 저장하는 레지스터
	//(uint64_t) syscall_entry: syscall_entry는 시스템 콜이 발생했을 때 가장 먼저 실행되는 커널 코드의 시작 주소이다. (보통 어셈블리로 작성된 진입점 함수)
	
	//CPU의 실행 포인터(RIP)를 syscall_entry 함수의 주소로 즉시 옮겨라
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	//SYSCALL 진입 시, CPU의 상태 플래그 (RFLAGS)를 어떻게 변경할지 결정하는 "안전 프로토콜 설정"단계
	//FLAG_IF: Interrupt Flag. 이 플래그가 켜져 있어야 하드웨어 인터럽트(키보드, 마우스, 타이머)를 받는다.
	//마스크 값에 FLAG_IF가 포함되어 있으므로 SYSCALL이 호출되면 CPU는 자동으로 인터럽트를 비활성화한다.
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* syscall_handler(struct intr_frame *f) 
	*역할: 모든 시스템 콜이 실제로 도착하는 중앙 처리소이다.
	*세부 동작 흐름:
		1. 시스템 콜 식별: 사용자 프로그램이 exec을 호출했는지, write를 호출했는지 알아낸다.
		호출된 시스템 콜의 고유 번호는 f->RDI 레지스터 값에 저장되어 있다.
		2. 인자 추출: 해당 시스템 콜에 필요한 인자들을 f가 가리키는 레지스터 값들에서 꺼내온다.
		(64비트 규약에 따라 두 번째 인자는 f->RSI, 세 번째는 f->RDX.. 순서로 들어있다.)
		3. 주소 유효성 검증: 인자로 받은 포인터(buffer 주소, 파일 이름 문자열 주소 등)가 유효한 사용자 영역에 있는지,
		커널 영역을 침범하지는 않는지 반드시 검사한다. 이 검사에 실패하면 프로세스를 즉시 종료시킨다.
		4. 기능 위임 및 실행: switch문을 통해 식별된 시스템 콜에 맞는 실제 처리 로직을 실행한다.
		예를 들어 SYS_WRITE이고 fd가 1이라면, 콘솔에 글자를 출력하는 putbuf() 함수를 호출한다.
		5. 결과 반환: 처리 결과를 f->RAX에 저장한다. syscall_handler가 리턴하면 커널은 f->RAX에 저장된 값을
		사용자 프로그램에게 시스템 콜 함수의 최종 반환 값으로 전달해준다.*/


	
	void check_address(void *addr, struct intr_frame *f){
		if(addr == NULL || !is_user_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL){
			f->R.rdi = -1;
			syscall_exit(f);
		}
	}

	void syscall_write(struct intr_frame *f UNUSED){
		int fd = f->R.rdi;
		char *buf = f->R.rsi;
		size_t size = f->R.rdx;
		check_address(buf, f);
			if(fd == 0){
				//에러
			}
			else if(fd == 1){
				putbuf(buf, size);
			}
			else{
			}
	}
	void syscall_exit(struct intr_frame *f UNUSED){
		int status = f->R.rdi;
		thread_current() ->exit_status = status;
		printf("%s: exit(%d)\n", thread_name(), status);
		thread_exit();
	}
	void syscall_create (struct intr_frame *f){
		const char *file = (const char *)f->R.rdi;
		unsigned size = (unsigned)f->R.rsi;
		check_address((void*)file, f);
		bool success = filesys_create(file, size);
        f->R.rax = success;
	}
	void syscall_open (struct intr_frame *f){
		char *file = f->R.rdi;
		check_address(file, f);
		struct file *open_file = filesys_open (file);
		if (open_file == NULL){
			f->R.rax = -1;
		}
		else{
			for(int i=2; i < FDT_COUNT_LIMIT; i++){
				if(thread_current()->fd_table[i] == NULL){
				thread_current()->fd_table[i] = open_file;
				f->R.rax = i;
				return;
			}
		}
			f->R.rax = -1; // 루프를 다 돔
	}
	}
	void syscall_close (struct intr_frame *f){
		int fd = f->R.rdi;
		
		// fd가 유효한 범위(2 ~ FDT_COUNT_LIMIT-1)에 있는지 확인
		if(fd < 2 || fd >= FDT_COUNT_LIMIT){
			return;
		}

		struct file *file_to_close = thread_current()->fd_table[fd];

		if(file_to_close != NULL){
			file_close(file_to_close);
			// fd 테이블의 해당 슬롯을 비워서 재사용 가능하게 함
			thread_current()->fd_table[fd] = NULL;
		}
	}
		

	

void
syscall_handler (struct intr_frame *f) {
	int syscall_num = f->R.rax;

	switch (syscall_num){

		/*void halt (void)*/
		case SYS_HALT:
			power_off();
			break;

		/*void exit (int status); (인자 1개: status)*/
		case SYS_EXIT:
			syscall_exit(f);
			break;

		/*int open (const char *file)*/
		case SYS_OPEN:
			syscall_open(f);
			break;
		
		/*void close (int fd)*/
		case SYS_CLOSE:
			syscall_close(f);
			break;

		case SYS_FORK:
			break;
		
		case SYS_EXEC:
			break;
		
		case SYS_WAIT:
			break;
		
		/*bool create (const char *file, unsigned initial_size)*/
		case SYS_CREATE:
			syscall_create(f);
			break;

		case SYS_REMOVE:
			break;

		case SYS_FILESIZE:
			break;
		
		case SYS_READ:
			break;

		/*int write (int fd, const void *buffer, unsigned size); (인자 3개: fd, buffer, size)*/
		case SYS_WRITE:
			syscall_write(f);
			break;

		case SYS_SEEK:
			break;
		
		case SYS_TELL:
			break;
		
		default:
			thread_exit();
			break;
	}
}

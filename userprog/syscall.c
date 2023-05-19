#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <stdio.h>
#include "threads/palloc.h"
#include "lib/kernel/stdio.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "vm/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void check_address(void *addr);
void half(void);
void exit(int status);
tid_t fork (const char *thread_name,struct intr_frame *f);
int exec (const char *cmd_line);
int wait (tid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size) ;
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);
struct file *process_get_file(int fd);

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
struct lock filesys_lock;

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
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	uint64_t sys_number = f->R.rax;
	struct thread *t = thread_current();
	t->stack_rsp = f->rsp;
	
    switch (sys_number)
    {
		case SYS_HALT:
				halt();
				break;
		case SYS_EXIT:
				exit(f->R.rdi);
				break;
		case SYS_FORK:
				f->R.rax = fork(f->R.rdi, f); //syscall만, process해야함
				break;
		case SYS_EXEC:
				exec(f->R.rdi); //syscall만, process해야함
				break;
		case SYS_WAIT:
				f->R.rax = wait(f->R.rdi); //syscall만, process해야함
				break;
		case SYS_CREATE:
				f->R.rax = create(f->R.rdi, f->R.rsi);
				break;
		case SYS_REMOVE:
				f->R.rax = remove(f->R.rdi);
				break;
		case SYS_OPEN:
				f->R.rax = open(f->R.rdi);
				break;
		case SYS_FILESIZE:
				f->R.rax = filesize(f->R.rdi);
				break;
		case SYS_READ:
				f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
				break;
		case SYS_WRITE:
				f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
				break;
		case SYS_SEEK:
				seek(f->R.rdi, f->R.rsi);
				break;
		case SYS_TELL:
				f->R.rax = tell(f->R.rdi);
				break;
		case SYS_CLOSE:
				close(f->R.rdi);
				break;
		case SYS_MMAP:
				f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
				break;
		case SYS_MUNMAP:
				munmap(f->R.rdi);
				break;
		default:
			exit(-1);
			break;
		}
}

void halt(void) {
    power_off();
}

// userprog/syscall.c
void exit(int status) {
    struct thread *curr = thread_current();
    curr->exit_status = status;                         // 종료시 상태를 확인, 정상종료면 state = 0
    printf("%s: exit(%d)\n", curr->name, status); // 종료 메시지 출력
    thread_exit();                                     // thread 종료
}

tid_t fork (const char *thread_name, struct intr_frame *f) {
	check_address(thread_name);
	return process_fork(thread_name, f);
}

int exec (const char *cmd_line) {
	check_address(cmd_line);

	int size = strlen(cmd_line) + 1; // null 값 포함한 파일 사이즈
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if ((fn_copy) == NULL) {
		exit(-1);
	}
	strlcpy(fn_copy, cmd_line, size);

	if (process_exec(fn_copy) == -1) {
		return -1;
	}

	NOT_REACHED();
	return 0;
}

int wait (tid_t pid) {
	return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int
open (const char *file) {
	check_address(file);
	struct file *open_file = filesys_open(file);
	
	if (open_file == NULL) {
		return -1;
	} 
	// 현재 프로세스의 fdt에 파일을 넣는 구문
	int fd = add_file_to_fdt(open_file);
	
	//add 함수 실행했는데, 가득 차서 -1을 받은 경우
	if (fd == -1) {
		file_close(open_file);
	}
	return fd;
}

// 파일 크기 정보 > file : inode > inode_disk : off_t length
int filesize (int fd) {
	//file.c의 file_length() 활용
	//fdt에 넣은 파일을 찾는 함수
	struct file *file = search_file_to_fdt(fd);
	if (file == NULL) {
		return -1;
	}
	return file_length(file);
}

int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	struct page *page = spt_find_page(&thread_current()->spt, pg_round_down(buffer));
	if (page != NULL && page->writable == 0)
		exit(-1);
	off_t read_byte = 0;
	uint8_t *read_buffer = (char *)buffer;
	lock_acquire(&filesys_lock);
	if (fd == 0)
	{
		char key;
		for (read_byte = 0; read_byte < size; read_byte++)
		{
			key = input_getc();	  // 키보드에 한 문자 입력받기
			*read_buffer++ = key; // read_buffer에 받은 문자 저장
			if (key == '\n')
			{
				break;
			}
		}
	}
	else if (fd == 1)
	{
		lock_release(&filesys_lock);
		return -1;
	}
	else
	{
		struct file *read_file = search_file_to_fdt(fd);
		if (read_file == NULL)
		{
			lock_release(&filesys_lock);
			return -1;
		}
		read_byte = file_read(read_file, buffer, size);
	}
	lock_release(&filesys_lock);
	return read_byte;
}

// int read (int fd, void *buffer, unsigned size) {
// 	/* 파일에 동시 접근이 일어날 수 있으므로 Lock 사용 */
// /* 파일 디스크립터를 이용하여 파일 객체 검색 */
// /* 파일 디스크립터가 0일 경우 키보드에 입력을 버퍼에 저장 후
// 버퍼의 저장한 크기를 리턴 (input_getc() 이용) */
// /* 파일 디스크립터가 0이 아닐 경우 파일의 데이터를 크기만큼 저
// 장 후 읽은 바이트 수를 리턴  */ 
// 	lock_acquire(&filesys_lock);
// 	if(fd == 0){
// 		input_getc();
// 		lock_release(&filesys_lock);
// 		return size;
// 	}
//   	struct file *fileobj= search_file_to_fdt(fd);
// 	size = file_read(fileobj,buffer,size);
// 	lock_release(&filesys_lock);	
// 	return size;
// }

int write (int fd, const void *buffer, unsigned size) {
	/* 파일에 동시 접근이 일어날 수 있으므로 Lock 사용 */
/* 파일 디스크립터를 이용하여 파일 객체 검색 */
/* 파일 디스크립터가 1일 경우 버퍼에 저장된 값을 화면에 출력
후 버퍼의 크기 리턴 (putbuf() 이용) */
/* 파일 디스크립터가 1이 아닐 경우 버퍼에 저장된 데이터를 크기
만큼 파일에 기록후 기록한 바이트 수를 리턴 */
	lock_acquire(&filesys_lock);
	if(fd == 1){
		 putbuf(buffer, size);  //문자열을 화면에 출력해주는 함수
		//putbuf(): 버퍼 안에 들어있는 값 중 사이즈 N만큼을 console로 출력
		lock_release(&filesys_lock);
		return size;
	}
	struct file *fileobj= search_file_to_fdt(fd);
	if(fileobj == NULL){
		lock_release(&filesys_lock);
		return -1;
	}
	
	size = file_write(fileobj,buffer,size);
	lock_release(&filesys_lock);
	return size;
}

// 열린 파일의 위치(offset)를 이동하는 syscall
// position 0은 파일의 시작 위치
void seek (int fd, unsigned position) {
	struct file *file = search_file_to_fdt(fd);
	// check_address(file); // 넣으면 TC Fail

	// stdin = 0 / stdout = 1
	if (fd <= 1) {
		return;
	}

	file_seek(file, position);
}

// 열린 파일의 위치(offset)을 알려주는 syscall
unsigned tell (int fd) {
	struct file *file = search_file_to_fdt(fd);
	// check_address(file); // 넣으면 TC Fail

	if (fd <= 1) {
		return;
	}
	file_tell(fd);
}

void close (int fd) {
	/* 해당 파일 디스크립터에 해당하는 파일을 닫음 */
	struct thread *curr = thread_current();
	curr->fdt[fd] = 0; /* 파일 디스크립터 엔트리 초기화 */
}

// checking validation of its arguments and calling do_mmap()
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	struct file *file = search_file_to_fdt(fd);
	
	if (file == NULL)
		return NULL;

	// 파일 시작점 페이지 정렬(PGSIZE에 맞게)되어 있는 지 확인
	if (offset % PGSIZE != 0)
		return NULL;

	// addr의 값이 유효한 주소인지 & 해당 주소의 시작점으로 정렬되는지 & 주소가 커널 영역에 해당하는지
	if (pg_round_down(addr) != addr || is_kernel_vaddr(addr))
		return NULL;
	
	// 현재 주소를 가지고 있는 페이지가 spt에 존재해야하므로, 유효한 페이지인지 확인
	if (spt_find_page(&thread_current()->spt, addr))
		return NULL;

	// addr이 NULL이 아니고 파일 길이(length)가 0 이상인지 확인
	if (addr == NULL || (long long)length <= 0)
		return NULL;
	
	// fd 값이 표준 입력이거나 표준 출력인지 확인
	if (fd == 0 || fd == 1)
		exit(-1);
	
	return do_mmap(addr, length, writable, file, offset);
}

void munmap (void *addr) {
	do_munmap(addr);
}

void check_address(void *addr){
	struct thread *curr = thread_current();
	if(addr== NULL || !is_user_vaddr(addr)) {
		exit(-1);
	} 
}
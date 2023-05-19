#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"

#include "vm/vm.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
struct file *search_file_to_fdt (int fd);
int add_file_to_fdt (struct file *file);
void process_close_file(int fd);

// project 3 - anon page
// aux로 넘겨줄 정보 값을 저장하는 구조체
// struct lazy_load_container {
//     struct file *file;
//     off_t ofs;
//     uint32_t read_bytes;
//     uint32_t zero_bytes;
// };

#endif /* userprog/process.h */

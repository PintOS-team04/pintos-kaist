#define VM
#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
#include "vm/vm.h"

struct segment {
	struct file *file;
	off_t offset;
	uint32_t page_read_bytes;
	uint32_t page_zero_bytes;
};

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
struct file *search_file_to_fdt (int fd);
int add_file_to_fdt (struct file *file);
void process_close_file(int fd);
bool lazy_load_segment (struct page *page, void *aux);
#endif /* userprog/process.h */

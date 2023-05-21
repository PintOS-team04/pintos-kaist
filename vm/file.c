/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
/* project 3 file mapped */
#include "userprog/process.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
struct lock filesys_lock;


/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
	lock_init(&filesys_lock);
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;
	struct lazy_load_container *container = (struct lazy_load_container *)page->uninit.aux;
	struct file_page *file_page = &page->file;
	file_page->file = container->file;
	file_page->file_ofs = container->ofs;
	file_page->read_bytes = container->read_bytes;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	// struct file_page *file_page UNUSED = &page->file;
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct file_page *file_page = &page->file;
	if (pml4_is_dirty(thread_current()->pml4, page->va)) {
			file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->file_ofs);
			pml4_set_dirty(thread_current()->pml4, page->va, 0);
		}

		pml4_clear_page(thread_current()->pml4, page->va);

}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
	lock_acquire(&filesys_lock);
	struct file *f = file_reopen(file);
	void * start_addr = addr; // 첫 시작 주소 저장, 후에 return에 사용하기 위함

	size_t read_bytes = file_length(f) < length ? file_length(f) : length;
	lock_release(&filesys_lock);
	size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(addr) == 0);
	ASSERT(offset % PGSIZE == 0)

	while (read_bytes > 0 || zero_bytes > 0) {

		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct lazy_load_container *container = (struct lazy_load_container*)malloc(sizeof(struct lazy_load_container));

		container->file = f;
		container->ofs = offset;
		container->read_bytes = page_read_bytes;
		container->zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer (VM_FILE, addr,
					writable, lazy_load_segment, container))
			return NULL;
		
		struct page *p = spt_find_page(&thread_current()->spt, addr);
		p->page_cnt = read_bytes / PGSIZE + 1;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}
	return start_addr;
}

/* Do the munmap */
void do_munmap (void *addr) {
	// printf("%d\n", pml4_is_dirty(thread_current()->pml4, addr));
	// dirty bit 0으로 설정
	struct page *page = spt_find_page(&thread_current()->spt, addr);
	if (page == NULL) {
		return;
	}
	off_t page_cnt = page->page_cnt;

	for (int i = 0; i < page->page_cnt; i++) {
		addr += PGSIZE;
		if (page) {
			spt_remove_page(&thread_current()->spt, page);

		}
		page = spt_find_page(&thread_current()->spt, addr);
		if (page== NULL){
			return;
		} ////////
	}

}

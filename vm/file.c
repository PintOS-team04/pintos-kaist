/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

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
	
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;
	struct segment *arg = (struct segment *)page->uninit.aux;

	struct file_page *file_page = &page->file;
	file_page->file = arg->file;
	file_page->file_ofs = arg->offset;
	file_page->read_bytes = arg->page_read_bytes;
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
	struct file_page *arg = &page->file;
	
	if (pml4_is_dirty(thread_current()->pml4, page->va)) {
		file_write_at(arg->file, page->va, arg->read_bytes, arg->file_ofs);
		pml4_set_dirty(thread_current()->pml4, page->va, 0);
	}
	pml4_clear_page(thread_current()->pml4, page->va);
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
	struct file *get_file = file_reopen(file);
	void *addr_origin = addr;

	uint32_t read_bytes = file_length(get_file) < length ? file_length(get_file) : length;
	uint32_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(addr) == 0);
	ASSERT(offset % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct segment *container = (struct segment *)malloc(sizeof(struct segment));
		container->file = get_file;
		container->offset = offset;
		container->page_read_bytes = page_read_bytes;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, container)) {
			return NULL;
		}

		struct page *p = spt_find_page(&thread_current()->spt, addr);
		p->page_cnt = read_bytes / PGSIZE + 1;

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}
	return addr_origin;
}

// /* Do the munmap */
// void
// do_munmap (void *addr) {
// 	while (true) {
// 		struct thread *curr = thread_current();
// 		struct page *find_page = spt_find_page(&curr->spt, addr);

// 		if (find_page == NULL) return NULL;

// 		struct segment *container = (struct segment *)find_page->uninit.aux;
// 		if (pml4_is_dirty(curr->pml4, find_page->va)) {
// 			file_write_at(container->file, addr, container->page_read_bytes, container->offset);
// 			pml4_set_dirty(curr->pml4, find_page->va, 0);
// 		}

// 		pml4_clear_page(curr->pml4, find_page->va);
// 		addr += PGSIZE;
// 	}
// }

/* Do the munmap */
void
do_munmap (void *addr) {
	struct page *page = spt_find_page(&thread_current()->spt, addr);
	off_t page_cnt = page->page_cnt;

	for (int i = 0; i < page_cnt; i++) {
		addr += PGSIZE;
		if (page) {
			spt_remove_page(&thread_current()->spt, page);
		}
		page = spt_find_page(&thread_current()->spt, addr);
	}
}
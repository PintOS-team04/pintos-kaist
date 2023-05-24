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

	struct file_page *file_page = &page->file;

	struct lazy_load_container *page_aux =  page->uninit.aux;

	file_page->file = page_aux->file;
	file_page->offset = page_aux->ofs;
	file_page->read_byte = page_aux->read_bytes;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;

	if (page == NULL)
		return false;

	struct file *file = file_page->file;
	off_t offset = file_page->offset;
	size_t page_read_bytes = file_page->read_byte;
	size_t page_zero_bytes = PGSIZE - page_read_bytes;

	file_seek(file, offset);
	file_read(file, kva, page_read_bytes);

	memset(kva + page_read_bytes, 0, page_zero_bytes);

	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	if (page == NULL)
		return false;

	if (pml4_is_dirty(thread_current()->pml4, page->va)) {
		file_write_at(file_page->file, page->va, file_page->read_byte, file_page->offset);
		pml4_set_dirty(thread_current()->pml4, page->va, 0);
	}
	// page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(thread_current()->pml4, page->va);
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
// static void
// file_backed_destroy (struct page *page) {
// 	struct file_page *file_page UNUSED = &page->file;
// }
static void
file_backed_destroy (struct page *page) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct file_page *arg = &page->file;
        if (pml4_is_dirty(thread_current()->pml4, page->va)){
            /* 어떤 offset부터 썼는지 확인 후 그 offset부터 write */
            file_write_at(arg->file, page->va, arg->read_byte, arg->offset);
            /* dirty bit 0으로 set */
            pml4_set_dirty(thread_current()->pml4, page->va, 0);
        }
	page->frame = NULL;
    pml4_clear_page(thread_current()->pml4, page->va);
    // struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	struct file * get_file = file_reopen(file); //건들이지 않기 위해서
	void * start_addr = addr; // 첫 시작 주소 저장, 후에 return에 사용하기 위함

	size_t read_bytes = file_length(get_file) < length ? file_length(get_file) : length;
	size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

	while (read_bytes > 0 || zero_bytes > 0) {

		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct lazy_load_container *container = (struct lazy_load_container*)malloc(sizeof(struct lazy_load_container));

		container->file = get_file;
		container->ofs = offset;
		container->read_bytes = page_read_bytes;
		container->zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer (VM_FILE, addr,
					writable, lazy_load_segment, container))
			return false;
		
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
// void
// do_munmap (void *addr) {
// 		while(true){
// 		struct thread *curr = thread_current();
// 		struct page *find_page = spt_find_page(&curr->spt, addr);

// 		if (find_page == NULL) {
//     		return NULL;
//     	}
// 		//destroy(find_page);

// 		struct lazy_load_container* container = (struct lazy_load_container*)find_page->uninit.aux;
		
// 		if (pml4_is_dirty(curr->pml4, find_page->va)){
// 			file_write_at(container->file, addr, container->read_bytes, container->ofs);
// 			pml4_set_dirty(curr->pml4,find_page->va,0);
// 		} 

// 		pml4_clear_page(curr->pml4, find_page->va); 
// 		addr += PGSIZE;
// 	}
// }

void
do_munmap (void *addr) {
	struct page *page = spt_find_page(&thread_current()->spt, addr);
	off_t page_cnt = page->page_cnt;

	for (int i = 0; i < page_cnt; i++) {
		addr += PGSIZE;
		if (page) {
			// spt_remove_page(&thread_current()->spt, page);
			destroy(page);
		}
		page = spt_find_page(&thread_current()->spt, addr);
	}
}

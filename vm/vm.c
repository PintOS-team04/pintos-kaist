/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "userprog/process.h"
#include <string.h>

#define USER_STACK_LIMIT (1 << 20)

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
	lock_init(&frame_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *page = (struct page *)calloc(1, sizeof(struct page));

		switch (VM_TYPE(type)) {
			case VM_ANON:
				// initializer = anon_initializer;
				uninit_new(page, upage, init, type, aux, anon_initializer);
				break;
			case VM_FILE:
				// initializer = file_backed_initializer;
				uninit_new(page, upage, init, type, aux, file_backed_initializer);
				break;
			default:
				uninit_new(page, upage, init, type, aux, NULL);
		}

		page->writable = writable;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct hash_elem *e;

	page = (struct page *)calloc(1, sizeof(struct page));
	page->va = pg_round_down(va);
	e = hash_find(&spt->pages, &page->spt_hash_elem);
	free(page);
	if (e != NULL)
		return hash_entry(e, struct page, spt_hash_elem);
	else
		return NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	// hash_insert()는 삽입에 성공했을 시, NULL을 old에 담아서 return
	struct hash_elem *e = hash_insert(&spt->pages, &page->spt_hash_elem);
	if (e == NULL) {
		succ = true;
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->pages, &page->spt_hash_elem);
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	for (struct list_elem *e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
		victim = list_entry(e, struct frame, frame_elem);

		if (victim->page == NULL)
			return victim;

		if (!pml4_is_accessed(thread_current()->pml4, victim->page->va))
			return victim;
		
		pml4_set_accessed(thread_current()->pml4, victim->page->va, 0);
	}
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = calloc(1, sizeof(struct frame));

	/* TODO: Fill this function. */
	frame->kva = palloc_get_page(PAL_USER);		// physical memory의 user pool에서 physical frame 주소 할당

	if (frame->kva == NULL) {					// vm_evict_frame() 호출하여 기존 p_memory에 존재하는 frame과
		free(frame);
		frame = vm_evict_frame();
		frame->page = NULL;
		return frame;

		PANIC("to do");							// 연결된 페이지 하나를 swap-out, 해당 frame 반환
	}

	list_push_back(&frame_table, &frame->frame_elem);

	frame->page = NULL;
	
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true);
	vm_claim_page(addr);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (addr == NULL || is_kernel_vaddr(addr))
		return false;

	if (not_present) {	
		page = spt_find_page(spt, addr);

		if (page == NULL) {	
			void *rsp_ = (void *)user ? f->rsp : thread_current()->stack_rsp;	// 어디에서 발생한 page fault인지 확인
			// USER_STACK 내에서 발생했는지, rsp 아래의 8바이트 위치에서 발생했는지
			if (USER_STACK > addr && addr >= USER_STACK - (1 << 20) && addr >= rsp_ - 8) {
				vm_stack_growth(pg_round_down(addr));
				return true;
			}
			return false;
		}	
		return vm_do_claim_page(page);
	}
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);		// p_memory와 연결할 페이지를 spt를 통해서 찾음
	if (page == NULL)
		return false;
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
// frame과 파라미터 page를 연결
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	struct thread *t = thread_current();
	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	pml4_set_page(t->pml4, page->va, frame->kva, page->writable);
	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->pages, page_hash, page_less, NULL);
}

bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED) {
	struct hash_iterator spt_iterator, dst_iterator;
	hash_first(&spt_iterator, &src->pages);

	while (hash_next(&spt_iterator)) {
		struct page *src_page = hash_entry(hash_cur(&spt_iterator), struct page, spt_hash_elem);
		if (VM_TYPE(src_page->operations->type) == VM_UNINIT) {
			vm_alloc_page_with_initializer(src_page->uninit.type, src_page->va, src_page->writable, src_page->uninit.init, src_page->uninit.aux);
			continue;
		}
		if (src_page->operations->type == VM_ANON) {
			vm_alloc_page(src_page->operations->type, src_page->va, src_page->writable);
			struct page *dst_page = spt_find_page(dst, src_page->va);
			vm_claim_page(src_page->va);
			memcpy(dst_page->frame->kva, src_page->frame->kva, (size_t)PGSIZE);
		}
		else if (src_page->operations->type == VM_FILE) {
			struct segment *aux = (struct segment *)malloc(sizeof(struct segment));
			aux->file = file_duplicate(src_page->file.file);
			aux->offset = src_page->file.file_ofs;
			aux->page_read_bytes = src_page->file.read_bytes;
			
			vm_alloc_page_with_initializer(src_page->operations->type, src_page->va, src_page->writable, NULL, aux);

			struct page *dst_page = spt_find_page(dst, src_page->va);
			file_backed_initializer(dst_page, VM_FILE, NULL);
			pml4_set_page(thread_current()->pml4, dst_page->va, src_page->frame->kva, src_page->writable);
			dst_page->frame = src_page->frame;
		}
	}
	return true;
}

void hash_elem_destroy(struct hash_elem *e, void *aux) {
	struct page *p = hash_entry(e, struct page, spt_hash_elem);
	destroy(p);
	free(p);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->pages, hash_elem_destroy);
}

/* Returns a hash value for page p. */
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, spt_hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, spt_hash_elem);
  const struct page *b = hash_entry (b_, struct page, spt_hash_elem);

  return a->va < b->va;
}
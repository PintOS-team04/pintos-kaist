/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"

#include "threads/thread.h"
#include "../include/userprog/process.h"
#include "threads/mmu.h"

unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
bool page_insert(struct hash *h, struct page *p);
void hash_elem_destroy(struct hash_elem *e, void *aux);
struct list frame_table;

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
// page_fault가 뜨면 해당 페이지의 vm_type을 정해주는 함수
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
		struct page *newpage = (struct page*)malloc(sizeof(struct page));

		// uninit.h
		typedef bool (*page_initializer)(struct page *, enum vm_type, void *kva);
		page_initializer new_initializer = NULL;

		switch (VM_TYPE(type))
		{
		case VM_ANON:
			new_initializer = anon_initializer;
			break;
		case VM_FILE:
			new_initializer = file_backed_initializer;
		default:
			break;
		}
		uninit_new(newpage, upage, init, type, aux, new_initializer); //uninit으로 만들어줌
		newpage->writable = writable;
		return spt_insert_page(spt, newpage);
		//palloc으로 new_page를 할당 받고
		// sutruct page *new_page = palloc_get_page(PAL_USER);
		//switch로 anon, file에 따라
		// switch(type)
		// uninit_new를 분리해서 호출해줌
		// case anon_:
		// uninit_new(new_page, upage, init, aux, anon_initializer); // init이 lazy_load_segment의 init임
	}
	// return true // 를 해줘야 load_세그먼트가 다시 불러도 넘어감
err:
	return false;
}

// project 3-1
/* Find VA from spt and return page. On error, return NULL. */
// 해시 테이블에서 인자로 받은 va가 있는지 찾는 함수, va가 속해있는 페이지가 해시테이블에 있으면 이를 리턴함
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	// struct page *page = NULL;
	/* TODO: Fill this function. */
	struct page *page = (struct page *)malloc(sizeof(struct page));
	struct hash_elem *e;

	page->va = pg_round_down(va); // 가상 주소를 내려 주소값의 시작 주소를 받음
	e = hash_find(&spt->spt_hash, &page->hash_elem);
	free(page); //더미 페이지이므로 찾았으면 free해줘야함
	// return page;
	if (e != NULL) {
		return hash_entry(e, struct page, hash_elem);
	} else {
		return NULL;
	}
}

// project 3-1
/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	//int succ = false;
	/* TODO: Fill this function. */
	
	//return succ;
	// return page_insert(&spt->spt_hash, page); // 원래 코드
	int succ = false;

	struct hash_elem *e = hash_insert(&spt->spt_hash, &page->hash_elem);
	if (e == NULL) {
		succ = true;
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	// struct frame *frame = NULL;
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame)); //?
	/* TODO: Fill this function. */
	frame->kva = palloc_get_page(PAL_USER);

	if (frame->kva == NULL) {
		PANIC("TODO");
	}
	frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page_with_initializer(VM_ANON, pg_round_down(addr), 1, NULL, NULL);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	// page-fault가 어떤 타입인지 확인
	// 1 va에 매핑되지 않은 경우
	// 2 bogus 인경우
	if (addr == NULL || is_kernel_vaddr(addr)) {
		return false;
	}

	if (not_present) {
		struct thread *curr = thread_current();
		void *user_rsp = user ? f->rsp : curr->user_rsp;
		// stack growth 해줘야하는 상황
		if (USER_STACK - 0x100000 <= addr && addr <= USER_STACK && user_rsp - 8 <= addr) {
			// vm_stack_growth(pg_round_down(addr));
			vm_stack_growth(addr);
		}
		page = spt_find_page(spt, addr);
		if (page == NULL) {
			return false;
		}
		return vm_do_claim_page (page);
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
	struct thread *curr = thread_current();
	page = spt_find_page(&curr->spt, va);
	if (page == NULL) {
		return false;
	}
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct thread *curr = thread_current();
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;
	// uint64_t pte = pml4e_walk(thread_current()->pml4, page->va,0);

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// if (install_page(page,frame,is_writable(&pte)) == true){
    //     return true;
    // }
    // return false;
    // return swap_in (page, frame->kva);
	pml4_set_page(curr->pml4, page->va, frame->kva, page->writable);

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);
}

// 부모 스레드의 spt 테이블의 page들을 복제
/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i; // 순회 객체

	hash_first(&i, &src->spt_hash);
	// src의 spt를 dst로 복사
	// 가져와야 할 것 : page, type, upage, writable
	while(hash_next(&i)) {
		struct page *parent_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type type = page_get_type(parent_page); // uninit 상태에서 미래 타입을 저장한 type
		//enum vm_type type = parent_page->uninit.type;
		void *upage = parent_page->va;
		bool writable = parent_page->writable;
		vm_initializer *init = parent_page->uninit.init;
		void *aux = parent_page->uninit.aux;
		
		// 부모가 uninit 상태인 경우
		// operations->type : 현재 타입
		if (parent_page->operations->type == VM_UNINIT) {
			if (!vm_alloc_page_with_initializer(type, upage, writable, init, aux)) {
				return false;
			}
		}
		else {
			if (!vm_alloc_page(type, upage, writable)) {
					return false;
			}
			if (!vm_claim_page(upage)) {
				return false;
			}
			struct page * child_page = spt_find_page(dst, upage);
				// 부모 페이지의 물리 메모리 정보를 자식에게 복사
			memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
			}
		}
		return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash, &hash_elem_destroy);
}

/* Returns a hash value for page p. */
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}

//spt_insert_page()를 위한 bool 함수
bool page_insert(struct hash *h, struct page *p) {
	if (!hash_insert(h,&p->hash_elem)) {
		return true;
	} else {
		return false;
	}
}

void hash_elem_destroy(struct hash_elem *e, void *aux) {
	struct page *p = hash_entry(e, struct page, hash_elem);
	destroy(p);
	free(p);
}
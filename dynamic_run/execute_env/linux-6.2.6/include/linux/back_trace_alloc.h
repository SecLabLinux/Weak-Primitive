#ifndef _BACK_TRACE_ALLOC_H
#define _BACK_TRACE_ALLOC_H


#ifdef CONFIG_BACK_TRACE_ALLOC

#define MAX_RECORD_CAPABLES 8
#define SYZKALLER_PROCESS_NAME_PREFIX "syz-executor"
#define SYZKALLER_PROCESS_NAME_PREFIX_LEN 12

enum BACK_TRACE_TYPE {
	BACK_TRACE_UNKNOWN = 0,
	BACK_TRACE_PAGE_ALLOC = 1,
	BACK_TRACE_PAGE_FREE = 2,
	BACK_TRACE_GENERAL_SLAB_ALLOC = 3,
	BACK_TRACE_GENERAL_SLAB_FREE = 4,
	BACK_TRACE_KMEM_CACHE_ALLOC = 5,
	BACK_TRACE_KMEM_CACHE_FREE = 6,
	BACK_TRACE_SYSCALL_ENTRY = 8,
	BACK_TRACE_SYSCALL_RETURN = 9,
	BACK_TRACE_KFREE_RCU = 10,
	BACK_TRACE_CALL_RCU = 11
};

struct capability_record {
	uint8_t		is_init_ns;
	uint8_t		capable;
	uint8_t     cap_opt;
};

struct back_trace_alloc_meta {
	atomic_t	do_not_record_alloc_page;
	atomic_t    do_not_record_kmalloc;
	atomic_t    capable_recorded;
	struct capability_record capables[MAX_RECORD_CAPABLES];
};

extern uint32_t back_trace_dump_stack;
// extern struct back_trace_alloc_meta global_back_trace_alloc_meta;

extern void init_back_trace_alloc_sysfs(void);
extern void exit_back_trace_alloc_sysfs(void);
extern void back_trace_assert(int condition, const char *fmt, ...);
extern void record_capability(struct task_struct *task, uint8_t is_init_ns, uint8_t cap, uint8_t opts);
extern void do_back_trace_record(char *meta_msg);

extern void register_back_trace_alloc_print_callback(void *write, void *read);

extern int back_trace_should_record(void);

extern void back_trace_call_rcu_callback(void* head, void *func);
extern void back_trace_kfree_rcu_callback(void* ptr);

#endif /* CONFIG_BACK_TRACE_ALLOC */

#endif // _BACK_TRACE_ALLOC_H

















/*
#ifdef CONFIG_BACK_TRACE_ALLOC
#include <linux/back_trace_alloc.h>
#endif

#ifdef CONFIG_BACK_TRACE_ALLOC
	atomic_set(&current->back_trace_alloc_meta.do_not_record_alloc_page, 1);
#endif

#ifdef CONFIG_BACK_TRACE_ALLOC
	// TODO: BACKTRACE NOTE
	atomic_set(&current->back_trace_alloc_meta.do_not_record_alloc_page, 1);
#endif

#ifdef CONFIG_BACK_TRACE_ALLOC
	back_trace_assert(atomic_read(&current->back_trace_alloc_meta.do_not_record_alloc_page) != 0, "Trace Do not Record Alloc Page not cleared in file %s, line %d: %s\n", __FILE__, __LINE__, __func__);
#endif

*/
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/cache.h>
#include <linux/uaccess.h>
#include <linux/sysfs.h> 
#include <linux/err.h>
#include "slab.h"

#include <linux/stacktrace.h>
#include <linux/stackdepot.h>

#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include <linux/object_fuzz.h>
#include <linux/back_trace_alloc.h>

#ifdef CONFIG_OBJECT_FUZZ

struct object_tester {
    char *testing_target_pattern;
    uint8_t in_testing:1;
    uint8_t has_returned_to_user:1;
    uint8_t has_executed_copy_from_or_to_user:1;
    uint8_t fuzz_after_copy_from_or_to_user:1;
    uint8_t fuzz_after_return_to_user:1;
    enum BACK_TRACE_TYPE testing_type;
    void *fuzz_object_base;
    uint64_t fuzz_object_size;
};

struct object_tester object_tester = {
    .testing_target_pattern = "", // FIXME: TEST
    .in_testing = 0,
    .fuzz_after_copy_from_or_to_user = 0,
    .fuzz_after_return_to_user = 0,
    .testing_type = 0,
    .has_returned_to_user = 0,
    .has_executed_copy_from_or_to_user = 0,
    .fuzz_object_base = NULL,
    .fuzz_object_size = 0,
};

void object_fuzz_change_bits(void *object_base, uint64_t object_size, uint64_t offset, uint64_t len) {
    // TODO
}

void object_fuzz_access_user_hook(const void *addr, uint64_t len) {
    object_tester.has_executed_copy_from_or_to_user = 1;
}

static int pattern_in_msg(char *msg, int len) {
    if (msg == NULL || len <= 0) {
        return 0;
    }
    if (object_tester.testing_target_pattern == NULL) {
        return 0;
    }
    if (strstr(msg, object_tester.testing_target_pattern) != NULL) {
        return 1;
    }
    return 0;
}

void object_fuzz_do_alloc_page(char *msg, int len) {
    char *p_start;
    char *p_end;
    int ret;
    char buf[32];

    if (!pattern_in_msg(msg, len)) {
        return;
    }
    if (object_tester.in_testing) {
        return;
    }
    object_tester.in_testing = true;
    object_tester.testing_type = BACK_TRACE_PAGE_ALLOC;
    object_tester.has_returned_to_user = 0;
    object_tester.has_executed_copy_from_or_to_user = 0;

    p_start = strstr(msg, "order: ");
    if (p_start == NULL) {
        return;
    }
    p_start += 7;
    p_end = strstr(p_start, ",");
    if (p_end == NULL) {
        return;
    }
    memcpy(buf, p_start, p_end - p_start);
    buf[p_end - p_start] = '\0';
    ret = kstrtol(buf, 10, (long *)&object_tester.fuzz_object_size);
    if (ret != 0) {
        return;
    }
    object_tester.fuzz_object_size = PAGE_SIZE << object_tester.fuzz_object_size;

    p_start = strstr(p_end, "addr: ");
    if (p_start == NULL) {
        return;
    }
    p_start += 6;
    p_end = strstr(p_start, "\n");
    if (p_end == NULL) {
        return;
    }
    memcpy(buf, p_start, p_end - p_start);
    buf[p_end - p_start] = '\0';
    ret = kstrtoull(buf, 16, (uint64_t *)&object_tester.fuzz_object_base);
    if (ret != 0) {
        return;
    }
}

void object_fuzz_do_free_page(char *msg, int len) {
    if (!object_tester.in_testing) {
        return;
    }
    if (object_tester.testing_type != BACK_TRACE_PAGE_ALLOC) {
        return;
    }
    if (!pattern_in_msg(msg, len)) {
        return;
    }
    object_tester.in_testing = false;
    object_tester.testing_type = BACK_TRACE_UNKNOWN;
    object_tester.has_returned_to_user = 0;
    object_tester.has_executed_copy_from_or_to_user = 0;
    object_tester.fuzz_object_base = NULL;
    object_tester.fuzz_object_size = 0;
}

void obj_fuzz_do_kmalloc(char *msg, int len) {
    char *p_start;
    char *p_end;
    int ret;
    char buf[32];

    if (!pattern_in_msg(msg, len)) {
        return;
    }
    if (object_tester.in_testing) {
        return;
    }
    object_tester.in_testing = true;
    object_tester.testing_type = BACK_TRACE_GENERAL_SLAB_ALLOC;
    object_tester.has_returned_to_user = 0;
    object_tester.has_executed_copy_from_or_to_user = 0;

    p_start = strstr(msg, "size: ");
    if (p_start == NULL) {
        return;
    }
    p_start += 6;
    p_end = strstr(p_start, ",");
    if (p_end == NULL) {
        return;
    }
    memcpy(buf, p_start, p_end - p_start);
    buf[p_end - p_start] = '\0';
    ret = kstrtol(buf, 16, (long *)&object_tester.fuzz_object_size);
    if (ret != 0) {
        return;
    }

    p_start = strstr(p_end, "addr: ");
    if (p_start == NULL) {
        return;
    }
    p_start += 6;
    p_end = strstr(p_start, "\n");
    if (p_end == NULL) {
        return;
    }
    memcpy(buf, p_start, p_end - p_start);
    buf[p_end - p_start] = '\0';
    ret = kstrtoull(buf, 16, (uint64_t *)&object_tester.fuzz_object_base);
    if (ret != 0) {
        return;
    }
}

void object_fuzz_do_kfree(char *msg, int len) {
    if (!object_tester.in_testing) {
        return;
    }
    if (object_tester.testing_type != BACK_TRACE_GENERAL_SLAB_ALLOC) {
        return;
    }
    if (!pattern_in_msg(msg, len)) {
        return;
    }
    object_tester.in_testing = false;
    object_tester.testing_type = BACK_TRACE_UNKNOWN;
    object_tester.has_returned_to_user = 0;
    object_tester.has_executed_copy_from_or_to_user = 0;
    object_tester.fuzz_object_base = NULL;
    object_tester.fuzz_object_size = 0;
}

void object_fuzz_do_kmem_cache_alloc(char *msg, int len) {
    char *p_start;
    char *p_end;
    int ret;
    char buf[32];
    struct kmem_cache *s;

    if (!pattern_in_msg(msg, len)) {
        return;
    }
    if (object_tester.in_testing) {
        return;
    }
    object_tester.in_testing = true;
    object_tester.testing_type = BACK_TRACE_KMEM_CACHE_ALLOC;
    object_tester.has_returned_to_user = 0;
    object_tester.has_executed_copy_from_or_to_user = 0;

    p_start = strstr(msg, "\ns: ");
    if (p_start == NULL) {
        return;
    }
    p_start += 4;
    p_end = strstr(p_start, ",");
    if (p_end == NULL) {
        return;
    }
    memcpy(buf, p_start, p_end - p_start);
    buf[p_end - p_start] = '\0';
    list_for_each_entry(s, &slab_caches, list) {
        if (strcmp(s->name, buf) == 0) {
            object_tester.fuzz_object_size = s->size;
            break;
        }
    }
    if (object_tester.fuzz_object_size == 0) {
        return;
    }

    p_start = strstr(p_end, "addr: ");
    if (p_start == NULL) {
        return;
    }
    p_start += 6;
    p_end = strstr(p_start, "\n");
    if (p_end == NULL) {
        return;
    }
    memcpy(buf, p_start, p_end - p_start);
    buf[p_end - p_start] = '\0';
    ret = kstrtoull(buf, 16, (uint64_t *)&object_tester.fuzz_object_base);
    if (ret != 0) {
        return;
    }
}

void object_fuzz_do_kmem_cache_free(char *msg, int len) {
    if (!object_tester.in_testing) {
        return;
    }
    if (object_tester.testing_type != BACK_TRACE_KMEM_CACHE_ALLOC) {
        return;
    }
    if (!pattern_in_msg(msg, len)) {
        return;
    }
    object_tester.in_testing = false;
    object_tester.testing_type = BACK_TRACE_UNKNOWN;
    object_tester.has_returned_to_user = 0;
    object_tester.has_executed_copy_from_or_to_user = 0;
    object_tester.fuzz_object_base = NULL;
    object_tester.fuzz_object_size = 0;
}

void object_fuzz_do_syscall_entry(char *msg, int len) {
}

void object_fuzz_do_syscall_return(char *msg, int len) {
    if (!object_tester.in_testing) {
        return;
    }
    object_tester.has_returned_to_user = 1;
}

void object_fuzz_do_kfree_rcu(char *msg, int len) {
}

void object_fuzz_do_rcu_start(char *msg, int len) {
}

void object_fuzz_event_hook(char *msg, int len) {
    if (msg == NULL || len <= 0) {
        return;
    }
    if (!memcmp(msg, "BACK_TRACE_ALLOC_PAGES_START", 28)) {
        object_fuzz_do_alloc_page(msg, len);
    } else if (!memcmp(msg, "BACK_TRACE_FREE_PAGE_START", 26)) {
        object_fuzz_do_free_page(msg, len);
    } else if (!memcmp(msg, "BACK_TRACE_KMALLOC_START", 24)) {
        obj_fuzz_do_kmalloc(msg, len);
    } else if (!memcmp(msg, "BACK_TRACE_KFREE_START", 22)) {
        object_fuzz_do_kfree(msg, len);
    } else if (!memcmp(msg, "BACK_TRACE_KMEM_CACHE_ALLOC_START", 33)) {
        object_fuzz_do_kmem_cache_alloc(msg, len);
    } else if (!memcmp(msg, "BACK_TRACE_KMEM_CACHE_FREE_START", 32)) {
        object_fuzz_do_kmem_cache_free(msg, len);
    } else if (!memcmp(msg, "BACK_TRACE_SYSCALL_ENTRY", 24)) {
        object_fuzz_do_syscall_entry(msg, len);
    } else if (!memcmp(msg, "BACK_TRACE_SYSCALL_RETURN", 25)) {
        object_fuzz_do_syscall_return(msg, len);
    } else if (!memcmp(msg, "BACK_TRACE_KFREE_RCU_START", 26)) {
        object_fuzz_do_kfree_rcu(msg, len);
    } else if (!memcmp(msg, "BACK_TRACE_CALL_RCU_START", 25)) {
        object_fuzz_do_rcu_start(msg, len);
    } else {
        return;
    }
}


#endif /* CONFIG_OBJECT_FUZZ */ 
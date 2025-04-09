#ifndef  MM_SHADOW_HEAP_H
#define  MM_SHADOW_HEAP_H

#include <linux/slab.h>
#include <linux/kfence.h>
#include "../slab.h"

#define OBJECT_CRUCIAL __attribute__((annotate("crucial"))) // 标记关键对象

// #define LONG_MAX 0x7fffffffffffffff

#define SHADOW_HEAP_HASH_SHIFT_2  4    // 从 4 位开始
#define SHADOW_HEAP_HASH_MASK_2   0xff  // 掩码取 8 位
#define SHADOW_HEAP_HASH_SIZE_2   0x100

#define SHADOW_HEAP_HASH_SHIFT_1  12   // 从 12 位开始
#define SHADOW_HEAP_HASH_MASK_1   0xff  // 掩码取 8 位
#define SHADOW_HEAP_HASH_SIZE_1   0x100 


// 第一层哈希表结构体
struct hash_table_level1 {
    struct hash_table_level2 *buckets[SHADOW_HEAP_HASH_SIZE_1];  // 每个桶指向一个二级哈希表
} __attribute__((aligned(sizeof(void *))));

// 第二层哈希表结构体
struct hash_table_level2 {
    struct hlist_head buckets[SHADOW_HEAP_HASH_SIZE_2];  // 每个桶指向一个hlist
    spinlock_t locks[SHADOW_HEAP_HASH_SIZE_2];
};

// 内存标记结构体
struct shadow_heap_memory_mark {
    void *ptr;
    void *shadow_ptr;
    struct hlist_node node;
};


extern struct hash_table_level1 *shadow_heap_hash_table;

extern void *kmalloc_shadow(size_t size, gfp_t flags);
extern void kfree_shadow(void *ptr);
extern long shadow_heap_calc_offset_in_object(void *ptr, unsigned long n);
extern struct shadow_heap_memory_mark *shadow_heap_lookup_ptr(struct hash_table_level1 *ht1, void *ptr);
extern void __init shadow_heap_init(void);

#ifdef CONFIG_SHADOW_HEAP
#define OBJECT_CRUCIAL_ASSIGN(obj, field, value) \
    do { \
        (obj)->field = (value); \
        void *shadow_obj = shadow_heap_lookup_ptr(shadow_heap_hash_table, (void *)(obj)); \
        if (shadow_obj) { \
            ((typeof(obj))shadow_obj)->field = (value); \
        } \
    } while (0)


#define OBJECT_CRUCIAL_MEMCPY_WRITE(dst, src, size) \
    do { \
        memcpy(dst, src, size); \
        long offset = shadow_heap_calc_offset_in_object(dst, size); \
        if (offset < 0) { \
            pr_err("Invalid address %px\n", dst); \
            BUG(); \
        } \
        void *shadow_obj = shadow_heap_lookup_ptr(shadow_heap_hash_table, dst-offset); \
        if (!shadow_obj) { \
            pr_err("Failed to find shadow object for %px\n", dst); \
            BUG(); \
        } \
        memcpy((void *)((unsigned long)shadow_obj + offset), src, size); \
    } while (0)

#define OBJECT_CRUCIAL_MEMCPY_CHECK(src, size) \
    do { \
        long offset = shadow_heap_calc_offset_in_object(src, size); \
        if (offset < 0) { \
            pr_err("Invalid address %px\n", src); \
            BUG(); \
        } \
        void *shadow_obj = shadow_heap_lookup_ptr(shadow_heap_hash_table, src-offset); \
        if (!shadow_obj) { \
            pr_err("Failed to find shadow object for %px\n", src); \
            BUG(); \
        } \
        if (memcmp((void *)((unsigned long)shadow_obj + offset), src, size) != 0) { \
            pr_err("Shadow object is not equal to object %px\n", src); \
            BUG(); \
        } \
    } while (0)




#define OBJECT_CRUCIAL_CHECK(obj, field) \
    do { \
        if ((obj)->field != ((typeof(obj))shadow_heap_lookup_ptr(shadow_heap_hash_table, (void *)(obj)))->field) { \
            pr_err("Object %px field %s is not equal to shadow object\n", (obj), #field); \
            BUG(); \
        } \
    } while (0)

#else // CONFIG_SHADOW_HEAP

#define OBJECT_CRUCIAL_ASSIGN(obj, field, value) \
    do { \
        (obj)->field = (value); \
    } while (0)


#define OBJECT_CRUCIAL_MEMCPY_WRITE(dst, src, size) \
    do { \
        memcpy(dst, src, size); \
    } while (0)

#define OBJECT_CRUCIAL_MEMCPY_CHECK(src, size) \
    do {} while (0)

#define OBJECT_CRUCIAL_CHECK(obj, field) \
    do {} while (0)

#endif // CONFIG_SHADOW_HEAP

#endif // MM_SHADOW_HEAP_H















/*
static int object_crucial_memcpy_write(void *dst, void *src, unsigned long size) {
    // 首先执行普通的 memcpy 操作
    memcpy(dst, src, size);

    // 如果启用了影子堆功能
#ifdef CONFIG_SHADOW_HEAP
    long offset = shadow_heap_calc_offset_in_object(dst, size);
    if (offset < 0) {
        pr_err("Invalid address %px\n", dst);
        return -EFAULT;
    }

    void *shadow_obj = shadow_heap_lookup_ptr(shadow_heap_hash_table, dst-offset);
    if (!shadow_obj) {
        pr_err("Failed to find shadow object for %px\n", dst);
        return -EFAULT;
    }

    memcpy((void *)((unsigned long)shadow_obj + offset), src, size);
#endif
}

static int object_crucial_memcpy_check(void *src, unsigned long size) {
    // 如果启用了影子堆功能
#ifdef CONFIG_SHADOW_HEAP
    long offset = shadow_heap_calc_offset_in_object(src, size);
    if (offset < 0) {
        pr_err("Invalid address %px\n", src);
        return -EFAULT;
    }

    void *shadow_obj = shadow_heap_lookup_ptr(shadow_heap_hash_table, src-offset);
    if (!shadow_obj) {
        pr_err("Failed to find shadow object for %px\n", src);
        return -EFAULT;
    }

    if (memcmp((void *)((unsigned long)shadow_obj + offset), src, size) != 0) {
        pr_err("Shadow object is not equal to object %px\n", src);
        return -EFAULT;
    }
#endif   
}
*/

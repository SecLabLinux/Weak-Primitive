#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/mutex.h>
// #include <linux/vmalloc.h>

#include "shadow_heap.h"

// 控制调试模式
#define DEBUG 0  // 在调试时将其设置为 1，关闭调试时设置为 0

// 调试日志宏
#if DEBUG
    #define shadow_heap_debug(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
    #define shadow_heap_debug(fmt, ...) do {} while (0)
#endif


// 锁保护影子堆
static DEFINE_MUTEX(shadow_heap_lock);
// static DEFINE_MUTEX(shadow_heap_mark_lock);

// 保护一级哈希表
// #define HT1_LOCK_INIT { __SPIN_LOCK_UNLOCKED(ht1_lock) }
// spinlock_t ht1_lock = HT1_LOCK_INIT;
DEFINE_SPINLOCK(ht1_lock);

struct kmem_cache *shadow_heap_memory_mark_cache;
struct hash_table_level1 *shadow_heap_hash_table;

static long __shadow_heap_calc_offset_in_object(const void *ptr, unsigned long n, 
                                             const struct slab *slab)
{
    struct kmem_cache *s;
	unsigned int offset;
	bool is_kfence = is_kfence_address(ptr);

	ptr = kasan_reset_tag(ptr);

	/* Find object and usable object size. */
	s = slab->slab_cache;

	/* Reject impossible pointers. */
	if (ptr < slab_address(slab))
        return -EFAULT;
    
    /* Find offset within object. */
	if (is_kfence)
		offset = ptr - kfence_object_start(ptr);
	else
		offset = (ptr - slab_address(slab)) % s->size;

    /* Adjust for redzone and reject if within the redzone. */
	if (!is_kfence && kmem_cache_debug_flags(s, SLAB_RED_ZONE)) {
		if (offset < s->red_left_pad)
			return -EFAULT;
		offset -= s->red_left_pad;
	}

    if (offset > s->size  || n > s->size - offset)
        return -EFAULT;

    return offset > LONG_MAX ? -EFAULT : offset;
    
}

// 返回地址在对应对象中的 offset
long shadow_heap_calc_offset_in_object(void *ptr, unsigned long n) {
    // unsigned long addr = (unsigned long)ptr;
    long ret = -EFAULT;
	unsigned long offset;
	struct folio *folio;

    if (!virt_addr_valid(ptr))
        return ret;

    folio = virt_to_folio(ptr);

    if(folio_test_slab(folio)) {
        ret = __shadow_heap_calc_offset_in_object(ptr, n, folio_slab(folio));
    } else if (folio_test_large(folio)) {
        offset = ptr - folio_address(folio);
        if (n > folio_size(folio) - offset)
            return -EFAULT;
        ret = offset > LONG_MAX ? -EFAULT : offset;
    }

    shadow_heap_debug("Calculating offset for %px, n = %lu, offset = %ld\n", ptr, n, ret);
    return ret;
}


static inline uint64_t hash_level1(uint64_t addr) {
    return (addr >> SHADOW_HEAP_HASH_SHIFT_1) & SHADOW_HEAP_HASH_MASK_1;
}

// 哈希函数：计算第二层哈希值
static inline uint64_t hash_level2(uint64_t addr) {
    return (addr >> SHADOW_HEAP_HASH_SHIFT_2) & SHADOW_HEAP_HASH_MASK_2;
}

// 初始化一级哈希表
static struct hash_table_level1 *create_hash_table_level1(void) {
    struct hash_table_level1 *ht1;
    int i;

    ht1 = kzalloc(sizeof(*ht1), GFP_KERNEL);
    if (!ht1)
        return NULL;

    // 初始化一级哈希表的每个桶
    for (i = 0; i < SHADOW_HEAP_HASH_SIZE_1; i++) {
        rcu_assign_pointer(ht1->buckets[i], NULL);
    }

    return ht1;
}

// 初始化二级哈希表
static struct hash_table_level2 *create_hash_table_level2(void) {
    struct hash_table_level2 *ht2;
    int i;

    ht2 = kzalloc(sizeof(*ht2), GFP_KERNEL);
    if (!ht2)
        return NULL;

    // 初始化每个桶为一个hlist_head
    for (i = 0; i < SHADOW_HEAP_HASH_SIZE_2; i++) {
        INIT_HLIST_HEAD(&ht2->buckets[i]);
        spin_lock_init(&ht2->locks[i]);
    }

    return ht2;
}

static void *shadow_heap_memory_mark_create(void);

static void *shadow_heap_memory_mark_create() {
    struct shadow_heap_memory_mark *mark;

    // mark = kzalloc(sizeof(*mark), GFP_KERNEL);
    mark = kmem_cache_alloc(shadow_heap_memory_mark_cache, GFP_KERNEL);
    if (!mark)
        return NULL;

    return mark;
}

static int shadow_heap_insert_ptr(struct hash_table_level1 *ht1, void *ptr, void *shadow_ptr) {
    struct hash_table_level2 *ht2;
    uint64_t hash1 = hash_level1((unsigned long)ptr);
    uint64_t hash2 = hash_level2((unsigned long)ptr);

    rcu_read_lock();
    ht2 = rcu_dereference(ht1->buckets[hash1]);

    // 如果二级哈希表为空，创建新的二级哈希表
    if (!ht2) {
        rcu_read_unlock();

        spin_lock(&ht1_lock);
        ht2  = rcu_dereference_protected(ht1->buckets[hash1], lockdep_is_held(&ht1_lock));
        if (!ht2) {
            ht2 = create_hash_table_level2();
            if (!ht2) {
                spin_unlock(&ht1_lock);
                return -ENOMEM;
            }
            rcu_assign_pointer(ht1->buckets[hash1], ht2);
        }
        spin_unlock(&ht1_lock);
        rcu_read_lock();
        ht2 = rcu_dereference(ht1->buckets[hash1]);
    }

    spin_lock(&ht2->locks[hash2]);
    struct shadow_heap_memory_mark *mark = shadow_heap_memory_mark_create();
    if (!mark) {
        spin_unlock(&ht2->locks[hash2]);
        rcu_read_unlock();
        return -ENOMEM;
    }

    mark->ptr = ptr;
    mark->shadow_ptr = shadow_ptr;

    shadow_heap_debug("Inserting ptr %px and shadow_ptr %px\n", ptr, shadow_ptr);

    // 将数据插入到二级哈希表的对应hlist中
    hlist_add_head(&mark->node, &ht2->buckets[hash2]);

    spin_unlock(&ht2->locks[hash2]);
    rcu_read_unlock();

    return 0;
}

struct shadow_heap_memory_mark *shadow_heap_lookup_ptr(struct hash_table_level1 *ht1, void *ptr) {
    uint64_t hash1 = hash_level1((unsigned long)ptr);
    uint64_t hash2 = hash_level2((unsigned long)ptr);
    struct shadow_heap_memory_mark *mark;
    void *result = NULL;

    struct hash_table_level2 *ht2;
    
    rcu_read_lock();
    ht2 = rcu_dereference(ht1->buckets[hash1]);
    if (!ht2) {
        rcu_read_unlock();
        return NULL;
    }

    spin_lock(&ht2->locks[hash2]);
    hlist_for_each_entry(mark, &ht2->buckets[hash2], node) {
        if (mark->ptr == ptr) {
            result = mark->shadow_ptr;
            shadow_heap_debug("Looking up ptr %px and shadow_ptr %px\n", ptr, result);
            break;
        }
    }
    spin_unlock(&ht2->locks[hash2]);

    rcu_read_unlock();
    return result;
}

// 从哈希表中删除ptr和shadow_ptr的映射关系，返回shadow_ptr
static void *shadow_heap_remove_ptr(struct hash_table_level1 *ht1, void *ptr) {
    struct hash_table_level2 *ht2;
    uint64_t hash1 = hash_level1((unsigned long)ptr);
    uint64_t hash2 = hash_level2((unsigned long)ptr);

    rcu_read_lock();
    ht2 = rcu_dereference(ht1->buckets[hash1]);
    if (!ht2) {
        rcu_read_unlock();
        return NULL;
    }

    struct shadow_heap_memory_mark *mark;
    struct hlist_node *tmp;
    void *ret = NULL;

    spin_lock(&ht2->locks[hash2]);
    hlist_for_each_entry_safe(mark, tmp, &ht2->buckets[hash2], node) {
        if (mark->ptr == ptr) {
            shadow_heap_debug("Removing ptr %px and shadow_ptr %px\n", ptr, mark->shadow_ptr);
            hlist_del(&mark->node);
            ret = mark->shadow_ptr;
            spin_unlock(&ht2->locks[hash2]);
            rcu_read_unlock();
            kmem_cache_free(shadow_heap_memory_mark_cache, mark);
            return ret;
        }
    }
    spin_unlock(&ht2->locks[hash2]);
    rcu_read_lock();
    return NULL;
}


void *kmalloc_shadow(size_t size, gfp_t flags) {
    void *ptr, *shadow_ptr;

    ptr = kmalloc(size, flags);
    if (!ptr)
        goto err_out;

    // shadow_ptr = vmalloc(size);
    shadow_ptr = kmalloc(size, flags| (1<<24));
    if (!shadow_ptr)
        goto err_free_ptr;

    // mutex_lock(&shadow_heap_mark_lock);

    if (!shadow_heap_hash_table) {
        pr_err("Shadow heap hash table is not initialized\n");
        // mutex_unlock(&shadow_heap_mark_lock);
        goto err_free_shadow;
    }    

    // 插入ptr和shadow_ptr的映射关系
    if (shadow_heap_insert_ptr(shadow_heap_hash_table, ptr, shadow_ptr) != 0) {
        pr_err("Failed to insert ptr and shadow_ptr mapping\n");
        // mutex_unlock(&shadow_heap_mark_lock);
        goto err_free_shadow;
    }

    // mutex_unlock(&shadow_heap_mark_lock);
    goto out;
    

err_free_shadow:
    kfree(shadow_ptr);
err_free_ptr:
    kfree(ptr);
err_out:
    ptr = NULL;
out:
    return ptr;
}

void kfree_shadow(void *ptr) {
    void *shadow_ptr = NULL;

    if (ptr == NULL)
        return;

    // mutex_lock(&shadow_heap_mark_lock);

    if (!shadow_heap_hash_table) {
        pr_err("Shadow heap hash table is not initialized\n");
        // mutex_unlock(&shadow_heap_mark_lock);
        kfree(ptr);
        return;
    }

    // 从哈希表中删除ptr和shadow_ptr的映射关系
    shadow_ptr = shadow_heap_remove_ptr(shadow_heap_hash_table, ptr);
    if (!shadow_ptr) {
        pr_err("Failed to remove ptr and shadow_ptr mapping\n");
        // mutex_unlock(&shadow_heap_mark_lock);
        return;
    }

    // mutex_unlock(&shadow_heap_mark_lock);

    kfree(ptr);
    kfree(shadow_ptr);

    return;
}

static int init_shadow_heap_hash_table(void);

static int init_shadow_heap_hash_table() {
    // 初始化哈希表
    shadow_heap_hash_table = create_hash_table_level1();
    if (!shadow_heap_hash_table) {
        pr_err("Failed to create hash table level 1\n");
        return -ENOMEM;
    }

    return 0;
}

static int init_shadow_heap(void) {
    int ret;
    mutex_lock(&shadow_heap_lock);

    // 初始化 kmem_cache
    shadow_heap_memory_mark_cache = kmem_cache_create("shadow_heap_cache", sizeof(struct shadow_heap_memory_mark), 0, 0, NULL);
    
    // 初始化哈希表
    if (init_shadow_heap_hash_table() != 0) {
        pr_err("Failed to initialize shadow heap hash table\n");
        ret = -ENOMEM;
        goto out;
    }

out:
    mutex_unlock(&shadow_heap_lock);
    return ret;
}


void __init shadow_heap_init(void) {
    pr_info("Initializing shadow heap.\n");

    // 初始化影子堆
    if (init_shadow_heap() != 0) {
        return;
    }
}

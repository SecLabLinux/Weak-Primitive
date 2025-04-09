#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sysfs.h> 
#include <linux/err.h>

#include <linux/stacktrace.h>
#include <linux/stackdepot.h>

#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include <linux/back_trace_alloc.h>
#include <linux/object_fuzz.h>
#ifdef CONFIG_BACK_TRACE_ALLOC
#define NETLINK_USER 31 
#define MAX_RECORD_LEN (0x1000-1)

#define DMA_START       0x40000

uint32_t back_trace_dump_stack = 0;
struct sock *nl_sk = NULL;
int user_pid = 0; 

struct back_trace_alloc_print_callback {
    int (*write) (uint64_t, char *, uint64_t);
    int (*read) (char *, uint64_t, uint64_t);
} back_trace_alloc_print_callback;

void register_back_trace_alloc_print_callback(void *write, void *read) {
    back_trace_alloc_print_callback.write = write;
    back_trace_alloc_print_callback.read = read;
}
EXPORT_SYMBOL(register_back_trace_alloc_print_callback);

struct kobject *kobj_ref;

static ssize_t  sysfs_show(struct kobject *kobj, 
                        struct kobj_attribute *attr, char *buf);
static ssize_t  sysfs_store(struct kobject *kobj, 
                        struct kobj_attribute *attr,const char *buf, size_t count);

static void backtrace_alloc_nl_recv_msg(struct sk_buff *skb) {

    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg="Hello from kernel";
    int res;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    msg_size=strlen(msg);

    nlh=(struct nlmsghdr*)skb->data;
    printk(KERN_INFO "Netlink received msg payload:%s\n",(char*)nlmsg_data(nlh));
    user_pid = nlh->nlmsg_pid; /*pid of sending process */

    skb_out = nlmsg_new(msg_size,0);

    if(!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    } 
    nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);  
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh),msg,msg_size);

    res=nlmsg_unicast(nl_sk,skb_out,user_pid);

    if(res<0)
        printk(KERN_INFO "Error while sending bak to user\n");
} 

void send_msg_to_user(char *msg, int msg_size) {
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    int res;
    
    skb_out = nlmsg_new(msg_size,0);
    
    if(!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }
    
    nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0); 
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    memcpy(nlmsg_data(nlh), msg, msg_size);
    
    res=nlmsg_unicast(nl_sk,skb_out,user_pid);
    
    if(res<0)
        printk(KERN_INFO "Error while sending bak to user\n");
}

int back_trace_should_record() {
    // Record syzkaller executor proccess
    if (!memcmp(current->comm, SYZKALLER_PROCESS_NAME_PREFIX, SYZKALLER_PROCESS_NAME_PREFIX_LEN))
        return 1;
    // Record kthread, for many alloctions and frees are called in kthread. And some RCU free is called in kthread.
    if (current->flags & PF_KTHREAD)
        return 1;
    // Record softirq, for RCU free is called (mostly) in softirq
    if (in_softirq())
        return 1;
    return 0;
}

/**
 * @brief Since some frees are called in call_rcu, we need to record the back trace.
 *        However, we can't determine the actual free information (e.g., slab) in call_rcu.
 *        Therefore, we record the address of `head` and `func` and find what is freed in
 *        python script later on.
 * 
 * @param head 
 * @param func 
 */
void back_trace_call_rcu_callback(void* head, void *func) {
	char back_trace_buf[0x100];
	int cur;
	if (atomic_read(&current->back_trace_alloc_meta.do_not_record_kmalloc)) {
		// atomic_set(&current->back_trace_alloc_meta.do_not_record_kmalloc, 0);
	}
	else if (!back_trace_should_record()) {
		// pass
	}
	else {
		if (back_trace_dump_stack) {
            cur = snprintf(back_trace_buf, 0x100, "BACK_TRACE_CALL_RCU_START\n");
			cur += snprintf(back_trace_buf + cur, 0x100 - cur, "head: %#lx, func: %#lx\n", head, func);
			do_back_trace_record(back_trace_buf);
		}
	}
}

void back_trace_kfree_rcu_callback(void* ptr) {
	char back_trace_buf[0x100];
	int cur;
	if (atomic_read(&current->back_trace_alloc_meta.do_not_record_kmalloc)) {
		// atomic_set(&current->back_trace_alloc_meta.do_not_record_kmalloc, 0);
	}
	else if (!back_trace_should_record()) {
		// pass
	}
	else {
		if (back_trace_dump_stack) {
            cur = snprintf(back_trace_buf, 0x100, "BACK_TRACE_KFREE_RCU_START\n");
			cur += snprintf(back_trace_buf + cur, 0x100 - cur, "ptr: %#lx\n", ptr);
			do_back_trace_record(back_trace_buf);
		}
	}
}

// static char legal_comm_chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ";

static unsigned int legal_comm(char *comm) {
    int comm_len = strlen(comm);
    if (comm_len > 0xf) {
        return 0;
    }
    for (int i = 0; i < comm_len; i++) {
        // if (!strchr(legal_comm_chars, comm[i])) {
        //     return 0;
        // }
        if (comm[i] < 0x20 || comm[i] > 0x7e) {
            return 0;
        }
    }
    return 1;
}

void do_back_trace_record(char *meta_msg) {
    unsigned long entries[0x30];
    unsigned int nr_entries;
    depot_stack_handle_t handle;
    char *sprint_buf;
    struct stack_record *found, *bucket;
    u32 hash;
    int cur;
    char comm_buf[0x10];
    char comm_buf_2[0x10];

    if (atomic_read(&current->back_trace_alloc_meta.do_not_record_alloc_page)) {
        return;
    }

    if (atomic_read(&current->back_trace_alloc_meta.do_not_record_kmalloc)) {
        return;
    }

    atomic_set(&current->back_trace_alloc_meta.do_not_record_alloc_page, 1);
    atomic_set(&current->back_trace_alloc_meta.do_not_record_kmalloc, 1);

    sprint_buf = kmalloc(MAX_RECORD_LEN+1, GFP_KERNEL);
    // printk("sprint_buf: %#lx\n", sprint_buf);
    cur = snprintf(sprint_buf, MAX_RECORD_LEN, "%s", meta_msg);
    // we cannot aquire the lock here, because we can be in the middle of a rcu callback.
    // this may cause rcu stall. a consequence of this compromise is that the result of comm may be incorrect. 
    do {
        memcpy(comm_buf, current->comm, 0x10);
        memcpy(comm_buf_2, current->comm, 0x10);
    } while (memcmp(comm_buf, comm_buf_2, 0x10) || !legal_comm(comm_buf));
    cur += snprintf(sprint_buf + cur, MAX_RECORD_LEN - cur, "pid: %d, comm: %s, tgid: %d\n", current->pid, comm_buf, current->tgid);

    if (memcmp(meta_msg, "BACK_TRACE_SYSCALL_ENTRY\n", 25) && memcmp(meta_msg, "BACK_TRACE_SYSCALL_RETURN\n", 26)) {
        cur += snprintf(sprint_buf + cur, MAX_RECORD_LEN - cur, "Recorded capabilities: \n");
        for (int i = 0; i < atomic_read(&current->back_trace_alloc_meta.capable_recorded); i++) {
            struct capability_record *capability_record = &current->back_trace_alloc_meta.capables[i];
            cur += snprintf(sprint_buf + cur, MAX_RECORD_LEN - cur, "[-] is_init_ns: %d, capable: %d, cap_opt: %d\n", capability_record->is_init_ns, capability_record->capable, capability_record->cap_opt);
        }
        cur += snprintf(sprint_buf + cur, MAX_RECORD_LEN - cur, "Dumping stack: \n");

        nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
        handle = stack_depot_save(entries, nr_entries, GFP_NOWAIT);
        cur += stack_depot_snprint(handle, sprint_buf + cur, MAX_RECORD_LEN - cur, 0);
    }
    cur += snprintf(sprint_buf + cur, MAX_RECORD_LEN - cur, "\n");
    if (cur >= MAX_RECORD_LEN) {
        printk("Back trace alloc: Might have overflowed the buffer\n");
    }
#ifdef CONFIG_OBJECT_FUZZ
    object_fuzz_event_hook(sprint_buf, cur);
#endif
    if (back_trace_alloc_print_callback.write) {
        back_trace_alloc_print_callback.write(DMA_START, sprint_buf, cur);
    }

    // nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
    // hash = hash_stack(entries, nr_entries);
    // bucket = stack_table[hash & stack_hash_mask];
    // found = find_stack(bucket, entries,
			 //   nr_entries, hash);
    // if (!found) {
    //     handle = stack_depot_save(entries, nr_entries, GFP_NOWAIT);
    //     cur += stack_depot_snprint(handle, sprint_buf + cur, MAX_RECORD_LEN - cur, 0);
    //     if (cur >= MAX_RECORD_LEN) {
    //         printk("Back trace alloc: Might have overflowed the buffer\n");
    //     }
    //     // send_msg_to_user(sprint_buf, cur);
    //     // printk("to write to sprint_buf: %#lx, cur: %#x\n", sprint_buf, cur);
    //     if (back_trace_alloc_print_callback.write) {
    //         back_trace_alloc_print_callback.write(DMA_START, sprint_buf, cur);
    //     }
    // } else {
    //     kfree(sprint_buf);
    //     // printk("Found stack: %p\n", found);
    // }

    // kfree(sprint_buf);
    atomic_set(&current->back_trace_alloc_meta.do_not_record_alloc_page, 0);
    atomic_set(&current->back_trace_alloc_meta.do_not_record_kmalloc, 0);
}

void record_capability(struct task_struct *task, uint8_t is_init_ns, uint8_t cap, uint8_t opts) {
    struct capability_record *capability_record;
    back_trace_assert(task == current, "record_capability: task != current");
    capability_record = &task->back_trace_alloc_meta.capables[atomic_read(&task->back_trace_alloc_meta.capable_recorded)];
    capability_record->is_init_ns = is_init_ns;
    capability_record->capable = cap;
    capability_record->cap_opt = opts;
}

void back_trace_assert(int condition, const char *fmt, ...)
{
    if (condition)
        return;
    va_list args;
    va_start(args, fmt);
    printk(KERN_ERR "back_trace_assert: ");
    vprintk(fmt, args);
    printk(KERN_ERR "\n");
    va_end(args);
    dump_stack();
    BUG();
}

static struct kobj_attribute ka = __ATTR(dump_stack, 0664, sysfs_show, sysfs_store);

static ssize_t sysfs_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
        // pr_info("Sysfs - Read!!!\n");
        return sprintf(buf, "%d\n", back_trace_dump_stack);
}
/*
** This function will be called when we write the sysfsfs file
*/
static ssize_t sysfs_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
        // pr_info("Sysfs - Write!!!\n");
        sscanf(buf,"%d", &back_trace_dump_stack);
        return count;
}

static int init_netlink_trace_alloc(void) {
    struct netlink_kernel_cfg cfg = {
        .input = backtrace_alloc_nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if(!nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    } else {
        printk(KERN_INFO "Netlink socket created.\n");
    }

    return 0;
}

static void exit_netlink_trace_alloc(void) {
    if (nl_sk != NULL) {
        netlink_kernel_release(nl_sk);
    }
}

void init_back_trace_alloc_sysfs(void)
{
    int error;
    kobj_ref = kobject_create_and_add("back_trace_alloc", kernel_kobj);
    if(!kobj_ref)
        return;
    ka.attr.mode = 0666;
    error = sysfs_create_file(kobj_ref, &ka.attr);
    if (error) {
        kobject_put(kobj_ref);
        sysfs_remove_file(kernel_kobj, &ka.attr);
        pr_info("failed to create the foo file in /sys/kernel/back_trace_alloc \n");
    }

    init_netlink_trace_alloc();
}

void exit_back_trace_alloc_sysfs(void)
{
    sysfs_remove_file(kobj_ref, &ka.attr);
    kobject_put(kobj_ref);

    exit_netlink_trace_alloc();
}

#endif
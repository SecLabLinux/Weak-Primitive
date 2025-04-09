/**
 * Detects usage of struct fields in conditional statements in Linux kernel
 * Tracks data flow of struct fields in conditional statements to identify potential CMFs.
 *
 * @name Linux Kernel Struct Field Condition Analysis
 * @kind path-problem
 * @problem.severity warning
 * @id cpp/linux/struct-field-condition
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking

/* This file defines predicates to identify and filter functions and macros related to memory allocation in the Linux kernel */

/* blackListFunction: identifies functions that should be excluded from analysis
 * These are allocation functions that we want to exclude from tracking since they are not related to heap allocation */

/* whiteListFunction: identifies functions that should be included in analysis
 * These are the standard kernel memory allocation functions that we want to track */

/* allocMacros: identifies macros related to memory allocation
 * These macros typically wrap the actual allocation functions */

predicate blackListFunction(Function f) {
  f.getName() in [
      "alloc_insn_page", "module_alloc", "malloc", "perf_trace_buf_alloc", "kasan_slab_alloc",
      "vmalloc", "vmalloc_node", "vzalloc", "vzalloc_node", "vmalloc_huge", "__vmalloc_node",
      "__vmalloc_array", "vmalloc_array", "__vcalloc", "vcalloc", "devm_kzalloc", "alloc_inode_sb",
      "is_vmalloc_addr", "vmalloc_to_page", "devm_kcalloc", "__vmalloc", "__alloc_percpu",
      "__alloc_percpu_gfp", "__tty_alloc_driver", "alloc_large_system_hash", "pcpu_alloc_chunk",
      "usb_alloc_urb", "sp_alloc_struct"
    ]
}

// UPDATE: linux 6.10
predicate whiteListFunction(Function f) {
  f.getName() in [
      "kstrdup", "kstrdup_const", "kstrndup", "kmemdup", "kmemdup_nul", "memdup_user",
      "vmemdup_user", "strndup_user", "memdup_user_nul", "kmemdup", "kmemdup_noprof", "krealloc",
      "krealloc_noprof", "__kmalloc", "__kmalloc_noprof", "kmem_cache_alloc",
      "kmem_cache_alloc_noprof", "kmem_cache_alloc_lru", "kmem_cache_alloc_lru_noprof",
      "kmem_cache_alloc_bulk", "kmem_cache_alloc_bulk_noprof", "__kmalloc_node",
      "__kmalloc_node_noprof", "kmem_cache_alloc_node", "kmem_cache_alloc_node_noprof",
      "kmalloc_trace", "kmalloc_trace_noprof", "kmalloc_node_trace", "kmalloc_node_trace_noprof",
      "kmalloc_large", "kmalloc_large_noprof", "kmalloc_large_node", "kmalloc_large_node_noprof",
      "kmalloc", "kmalloc_noprof", "kmalloc_node", "kmalloc_node_noprof", "kmalloc_array",
      "kmalloc_array_noprof", "krealloc_array", "krealloc_array_noprof", "kcalloc",
      "__kmalloc_node_track_caller", "kmalloc_node_track_caller_noprof", "kmalloc_array_node",
      "kmalloc_array_node_noprof", "kcalloc_node", "kmem_cache_zalloc", "kzalloc", "kzalloc_noprof",
      "kzalloc_node", "kvmalloc_node", "kvmalloc_node_noprof", "kvzalloc", "kvzalloc_node",
      "kvmalloc_array", "kvmalloc_array_noprof", "kvcalloc", "kvrealloc", "kvrealloc_noprof"
    ]
}

predicate allocMacros(Macro m) {
  m.getName() in [
      "kmemdup", "kmemdup_noprof", "krealloc", "krealloc_noprof", "__kmalloc", "__kmalloc_noprof",
      "kmem_cache_alloc", "kmem_cache_alloc_noprof", "kmem_cache_alloc_lru",
      "kmem_cache_alloc_lru_noprof", "kmem_cache_alloc_bulk", "kmem_cache_alloc_bulk_noprof",
      "__kmalloc_node", "__kmalloc_node_noprof", "kmem_cache_alloc_node",
      "kmem_cache_alloc_node_noprof", "kmalloc_trace", "kmalloc_trace_noprof", "kmalloc_node_trace",
      "kmalloc_node_trace_noprof", "kmalloc_large", "kmalloc_large_noprof", "kmalloc_large_node",
      "kmalloc_large_node_noprof", "kmalloc", "kmalloc_noprof", "kmalloc_node",
      "kmalloc_node_noprof", "kmalloc_array", "kmalloc_array_noprof", "krealloc_array",
      "krealloc_array_noprof", "kcalloc", "__kmalloc_node_track_caller",
      "kmalloc_node_track_caller_noprof", "kmalloc_array_node", "kmalloc_array_node_noprof",
      "kcalloc_node", "kmem_cache_zalloc", "kzalloc", "kzalloc_noprof", "kzalloc_node",
      "kvmalloc_node", "kvmalloc_node_noprof", "kvzalloc", "kvzalloc_node", "kvmalloc_array",
      "kvmalloc_array_noprof", "kvcalloc", "kvrealloc", "kvrealloc_noprof"
    ]
}

/**
 * These structs are either:
 * 1. Kernel objects that cannot be accessed by unprivileged users
 * 2. Objects that may appear to be interesting but have no actual security impact
 * 
 * We exclude them from analysis to reduce false positives and focus on more relevant structures.
 */

predicate blackListStruct(Struct s) {
  s.getName() in [
      "list_head", "hlist_head", "fwnode_handle", "page", "folio", "dentry", "xa_node",
      "return_instance", "elf64_hdr", "elf64_shdr", "elf64_phdr", "elf32_shdr", "elf32_phdr",
      "elf32_hdr", "trace_seq", "kvm_io_bus", "ptp_extts_event", "scsi_dev_info_list",
      "scsi_dev_info_list_table", "async_scan_data", "work_queue_wrapper", "storvsc_scan_work",
      "target_core_file_cmd", "tcmu_tmr", "uart_8250_em485", "tty_audit_buf", "saved_alias",
      "dma_pool", "dma_page", "assoc_array_shortcut", "aa_buffer", "mod_initfree", "work_struct",
      "module_use", "sk_buff", "inode", "device", "net_device", "task_struct", "sock", "net",
      "file", "pci_dev", "nlattr", "super_block", "xfs_mount", "bpf_prog", "seq_file", "xfs_inode",
      "bio", "vm_area_struct", "mm_struct", "work_struct", "perf_event", "module", "mutex",
      "kobject", "in6_addr", "cred", "buffer_head", "xfs_buf", "request", "attribute", "cpumask",
      "resource", "scatterlist", "path", "attribute_group", "address_space", "notifier_block",
      "kmem_cache", "ctl_table", "xfs_da_args", "xfs_trans", "devlink", "nf_conn", "dst_entry",
      "xfs_btree_cur", "nfs_server", "mem_cgroup", "ata_port", "cgroup", "nfs_client",
      "TCP_Server_Info", "xlog", "scsi_device", "Scsi_Host", "se_device", "net_bridge_port",
      "cifs_tcon", "bpf_insn", "kvec", "pci_bus", "svc_fh", "kernfs_node", "nfs_fh", "nfs4_client",
      "rb_root", "bio_vec", "phy_device", "xfs_bmbt_irec", "gendisk", "configfs_attribute",
      "xfs_dquot", "input_dev", "xfs_perag", "cifs_sb_info", "ata_link", "nfs_pgio_header",
      "nfs4_state", "cpufreq_policy", "tpm_chip", "pnfs_layout_segment", "nfs_page",
      "perf_event_context", "clock_event_device", "nfsd_file", "iattr", "cifs_ses", "shash_desc",
      "cfs_rq", "xfs_buf_log_item", "pnfs_layout_hdr", "thermal_zone_device",
      "__kernel_sockaddr_storage", "nfs_fattr", "virtqueue", "cifsFileInfo", "nfs_open_context",
      "hv_device", "bin_attribute", "slab", "serio", "desc_struct", "bpf_prog_array",
      "bpf_tramp_link", "bpf_tramp_links", "bpf_array", "bpf_binary_header", "sock_filter",
      "cacheinfo", "node", "boot_params", "msr", "workqueue_attrs", "blocking_notifier_head",
      "mem_section", "mem_section_usage", "per_cpu_nodestat", "lru_gen_mm_walk", "kernfs_ops",
      "kernfs_global_locks", "kernfs_fs_context", "kernfs_root", "kernfs_iattrs", "kobj_uevent_env",
      "kobj_map_init", "stack_depot_init", "mem_cgroup_tree_per_node", "inet_peer_base",
      "key_restriction", "in_device", "seg6_pernet_data", "inet_diag_handler", "ioam6_pernet_data",
      "proc_net_ns_init", "zone_device", "demotion_nodes", "xt_af", "netlink_table", "lsm_info",
      "plist_head", "cdev", "tty_driver", "platform_device", "pcpu_sw_netstats", "pcpu_lstats",
      "kimage", "memory_dev_type", "arpt_replace", "ipt_replace", "ip6t_replace", "sfq_init",
      "pcpu_chunk", "atkbd", "xenkbd_info", "devres", "pcpu_block_md", "ext4_sb_info", "alloc_tag"
    ]
}

predicate isAllocFunction(Function f) {
  (
    f.getName().regexpMatch(".*alloc.*") or
    whiteListFunction(f)
  ) and
  inScope(f) and
  not blackListFunction(f)
}

predicate initFunction(Function f) {
  exists(MacroInvocation mi |
    mi.getMacroName() = "__init" and
    f.getDefinitionLocation().getFile() = mi.getActualLocation().getFile() and
    (
      f.getDefinitionLocation().getStartLine() = mi.getActualLocation().getStartLine() or
      f.getDefinitionLocation().getStartLine() = mi.getActualLocation().getStartLine() + 1 or
      f.getDefinitionLocation().getStartLine() = mi.getActualLocation().getStartLine() + 2
    )
  )
}

predicate inScope(Function f) {
  exists(string file |
    file = f.getDefinitionLocation().getFile().toString() and
    file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/tools/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/scripts/.*")
  ) and
  not initFunction(f) and
  not blackListFunction(f)
}

/**
 * Determines if a DataFlow::Node is in scope for analysis.
 * Excludes nodes from files that are less relevant for vulnerability exploitation:
 * - Virtualization related code (KVM, Xen, etc.)
 * - Device drivers
 * - Niche filesystems
 * - Platform specific code
 * - Debug/tracing functionality
 * These excluded components typically contain objects that cannot be effectively 
 * leveraged in exploit development.
 */

predicate inScopeNode(DataFlow::Node n) {
  exists(string file |
    file = n.getLocation().getFile().toString() and
    file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/include/linux/platform_data/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/acpi/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kernel/sev.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/dma/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/block/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/trace/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/power/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/xen/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kvm/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/pci/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/boot/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/platform/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/hyperv/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/ia32/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/events/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kernel/cpu/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kernel/kvm.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kernel/kprobes/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kernel/apic/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/events/intel/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/.*bpf.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/xen/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/cdrom/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/iommu/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/net/xen-netback/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/nvme/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/pnp/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/md/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/ptp/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/vfio/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/hv/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/vhost/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/virtio/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/virt/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/cpufreq/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/firmware/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/ata/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/block/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/pci/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/char/tpm/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/misc/vmw_vmci/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/net/9p/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/net/vmw_vsock/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/mm/vmalloc.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/kprobes.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/events/uprobes.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/params.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/power/console.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/tracepoint.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/locking/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/sched/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/irq/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/security/integrity/ima/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/block/xen-blkfront.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/virt/kvm/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/include/asm/kvm.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/audit.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/net/netfilter/ipvs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/net/netfilter/nf_conntrack_.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/net/ethernet/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/net/virtio_net.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/crypto/virtio/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/mtd/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/clk/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/scsi/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/net/hyperv/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/net/xen-netfront.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/input/serio/hyperv-keyboard.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/input/misc/xen-kbdfront.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/input/serio/pcips2.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/iio/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/cpufreq/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/acpi/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/media/usb/dvb-usb-v2/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/block/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/char/virtio_console.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/comedi/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/usb/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/gpu/drm/vmwgfx/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/thunderbolt/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/block/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/irq/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/nfsd/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/nfs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/smb/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/cachefiles/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/debugfs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/jbd2/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/isofs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/quota/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/kernfs/mount.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/squashfs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/fscache/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/xfs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/.*/intel/.*") and
    // no ERRxxx
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/include/linux/err.h")
  )
}

predicate inScopeExpr(Expr e) {
  exists(string file |
    file = e.getLocation().getFile().toString() and
    file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/include/linux/platform_data/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/acpi/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kernel/sev.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/dma/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/block/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/trace/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/power/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/xen/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kvm/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/pci/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/boot/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/platform/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/hyperv/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/ia32/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/events/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kernel/cpu/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kernel/kvm.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kernel/kprobes/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/kernel/apic/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/events/intel/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/.*bpf.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/xen/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/cdrom/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/iommu/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/net/xen-netback/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/nvme/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/pnp/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/md/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/ptp/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/vfio/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/hv/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/vhost/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/virtio/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/virt/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/cpufreq/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/firmware/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/ata/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/block/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/pci/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/char/tpm/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/misc/vmw_vmci/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/net/9p/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/net/vmw_vsock/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/mm/vmalloc.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/kprobes.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/events/uprobes.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/params.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/power/console.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/tracepoint.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/locking/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/sched/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/irq/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/security/integrity/ima/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/block/xen-blkfront.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/virt/kvm/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/arch/x86/include/asm/kvm.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/audit.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/net/netfilter/ipvs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/net/netfilter/nf_conntrack_.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/net/ethernet/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/net/virtio_net.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/crypto/virtio/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/mtd/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/clk/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/scsi/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/net/hyperv/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/net/xen-netfront.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/input/serio/hyperv-keyboard.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/input/misc/xen-kbdfront.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/input/serio/pcips2.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/iio/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/cpufreq/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/acpi/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/media/usb/dvb-usb-v2/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/block/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/char/virtio_console.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/comedi/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/usb/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/gpu/drm/vmwgfx/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/drivers/thunderbolt/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/block/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/kernel/irq/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/nfsd/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/nfs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/smb/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/cachefiles/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/debugfs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/jbd2/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/isofs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/quota/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/kernfs/mount.c") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/squashfs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/fscache/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/fs/xfs/.*") and
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/.*/intel/.*") and
    // no ERRxxx
    not file.regexpMatch("/root/pwn/linux-[\\d\\.]+\\d+/include/linux/err.h")
  )
}

predicate inScopeFc(FunctionCall fc) { inScopeExpr(fc) }

Type getTypeOfFunctionCall(FunctionCall fc) {
  result = fc.getParent().(AssignExpr).getLValue().getType() or
  result = fc.getParent().(ConditionalExpr).getParent().(AssignExpr).getLValue().getType() or
  result = fc.getParent().(Initializer).getDeclaration().getADeclarationEntry().getType() or
  result = fc.getParent().(ReturnStmt).getEnclosingFunction().getType()
}

Type getTypeofMacroInvocation(MacroInvocation mi) {
  result = mi.getExpr().getParent*().(AssignExpr).getLValue().getType() or
  result =
    mi.getExpr().getParent*().(ConditionalExpr).getParent().(AssignExpr).getLValue().getType() or
  result = mi.getExpr().getParent*().(Initializer).getDeclaration().getADeclarationEntry().getType() or
  result = mi.getExpr().getParent*().(ReturnStmt).getEnclosingFunction().getType()
}

predicate allocableObject_2(Function f, Struct s) {
  isAllocFunction(f) and
  exists(FunctionCall fc |
    getTypeOfFunctionCall(fc).(DerivedType).getBaseType*() = s and
    fc.getTarget() = f and
    inScopeFc(fc) and
    not blackListStruct(s) and
    not s instanceof LocalStruct
  )
}

predicate allocableObject_macro(Macro m, Struct s) {
  allocMacros(m) and
  exists(MacroInvocation mi |
    mi.getMacro() = m and
    getTypeofMacroInvocation(mi).(DerivedType).getBaseType*() = s and
    not blackListStruct(s) and
    not s instanceof LocalStruct
  )
}

predicate allocableObject_macro_mi(Macro m, Struct s, MacroInvocation mi) {
  allocMacros(m) and
  mi.getMacro() = m and
  getTypeofMacroInvocation(mi).(DerivedType).getBaseType*() = s and
  not blackListStruct(s) and
  not s instanceof LocalStruct
}

predicate allocableObject_2_fc(Function f, Struct s, FunctionCall fc, Function sf, string file) {
  isAllocFunction(f) and
  getTypeOfFunctionCall(fc).(DerivedType).getBaseType*() = s and
  fc.getTarget() = f and
  sf = fc.getEnclosingFunction() and
  inScopeFc(fc) and
  not blackListStruct(s) and
  file = fc.getLocation().getFile().toString()
}

predicate isDestroyFunction(Function f) {
  (
    f.getName().regexpMatch(".*destroy.*")
    or
    f.getName().regexpMatch(".*free.*")
    or
    f.getName().regexpMatch(".*put.*")
    or
    f.getName().regexpMatch(".*delete.*")
    or
    f.getName().regexpMatch(".*cleanup.*")
    or
    (
      f.getName().matches("%\\_del") or
      f.getName().matches("del\\_%") or
      f.getName().matches("%\\_del\\_%")
    ) and
    not f.getName().matches("%list%")
  ) and
  (
    not f.getName().matches("%puts%") and
    not f.getName().matches("%putchar%") and
    not f.getName().matches("%putstr%") and
    not f.getName().matches("%puthex%") and
    not f.hasName("free") and
    not f.getName().matches("%freeze%") and
    not f.hasName("seq_puts") and
    not f.getName().matches("%input%") and
    not f.hasName("seq_putc") and
    not f.hasName("nla_put")
  )
}

predicate hasChildExpr(Stmt s, Expr e) {
  (
    s.(ExprStmt).getExpr() = e or
    s.(ReturnStmt).getExpr() = e
  )
  or
  exists(Stmt child |
    s.getChildStmt() = child and
    hasChildExpr(child, e)
  )
}

module LengthFieldConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Struct s, FieldAccess fa |
      s = fa.getQualifier().getType().stripType() and
      (
        exists(Function f | allocableObject_2(f, s)) or
        exists(Macro m | allocableObject_macro(m, s))
      ) and
      fa.getTarget().getType().getUnspecifiedType() instanceof IntegralType and
      source.asExpr() = fa
    )
  }

  // Sink for if statements
  predicate isSink(DataFlow::Node sink) {
    exists(Expr condition |
      exists(Expr sink_expr |
        sink_expr = sink.asExpr() and
        sink_expr = condition.getAChild*() and
        sink_expr.getType().getUnspecifiedType() instanceof IntegralType and
        not sink_expr.getAChild*().toString().matches("%err%") and
        not sink_expr.getAChild*().toString().matches("%ERR%")
      ) and
      exists(IfStmt is |
        is.getCondition() = condition and
        exists(int num_stmt |
          num_stmt = count(is.getThen().getChildStmt()) and
          num_stmt < 5
        ) and
        not exists(Stmt child_st |
          (
            child_st = is.getThen().getChildStmt*() or
            child_st = is.getElse().getChildStmt*()
          ) and
          (
            child_st instanceof ReturnStmt or
            child_st instanceof JumpStmt
          )
        ) and
        exists(FunctionCall fc |
          (
            fc.getEnclosingStmt() = is.getThen() or
            fc.getEnclosingStmt() = is.getThen().getChildStmt*()
          ) and
          exists(Function fDestroy |
            fc.getTarget() = fDestroy and
            isDestroyFunction(fDestroy)
          ) and
          not exists(VariableAccess va_fc_arg, AssignExpr ae, VariableAccess va_assigned |
            va_fc_arg = fc.getAnArgument() and
            va_assigned = ae.getLValue() and
            va_assigned.getTarget() = va_fc_arg.getTarget() and
            ae.getEnclosingBlock() = fc.getEnclosingBlock()
          ) and
          not exists(FunctionCall list_del_fc |
            list_del_fc.getTarget().getName().matches("%list_del%") and
            list_del_fc.getEnclosingBlock() = fc.getEnclosingBlock() and
            list_del_fc.getASuccessor*() = fc
          )
        )
      )
    )
  }
}

module LengthFieldFlow = TaintTracking::Global<LengthFieldConfiguration>;

import LengthFieldFlow::PathGraph

from
  Struct s, FieldAccess fa, int size, int offset, string file, LengthFieldFlow::PathNode source,
  LengthFieldFlow::PathNode sink
where
  size = s.getSize() and
  offset = fa.getTarget().getByteOffset() and
  file = fa.getLocation().getFile().toString() and
  s = fa.getQualifier().getType().stripType() and
  source.getNode().asExpr() = fa and
  LengthFieldFlow::flowPath(source, sink)

select sink.getNode(), source, sink,
  "$@ has path to $@, Struct $@, Size  " + size.toString() + " Offset " + offset.toString() +
    " File " + file, source.getNode(), source.getNode().asExpr().toString(), sink.getNode(),
  sink.getNode().asExpr().toString(), s, s.getName()

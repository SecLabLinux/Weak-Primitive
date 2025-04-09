#!/usr/bin/env python3
import gdb
import time
import json
import enum
import pprint
import string
import random

# for our case kaslr is disabled, so we can hardcode the address here
vmemmap_base = 0xffffea0000000000
direct_map_base = 0xffff888000000000

ID_PREFIX_LEN = 16
id_prefix = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase +
                                   string.digits, k=ID_PREFIX_LEN-1)) + '_'
trace_id = 0

# Enum of backtrace type


class BackTraceType(enum.Enum):
    UNKOWN = 0
    PAGE_ALLOC = 1
    PAGE_FREE = 2
    GENERAL_SLAB_ALLOC = 3
    GENERAL_SLAB_FREE = 4
    KMEM_CACHE_ALLOC = 5
    KMEM_CACHE_FREE = 6
    CAP_CHECK = 7
    SYSCALL_ENTRY = 8
    SYSCALL_RETURN = 9

# Trace record


class TraceRecord:
    def __init__(self, trace_id, trace_type, comm, pid, backtrace):
        self.trace_id = trace_id
        self.trace_type = trace_type
        self.comm = comm
        self.pid = pid
        self.backtrace = backtrace

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)


class PageAllocRecord(TraceRecord):
    def __init__(self, trace_id, trace_type, comm, pid, backtrace, addr, order):
        super().__init__(trace_id, trace_type, comm, pid, backtrace)
        self.addr = addr
        self.order = order
        self.is_pair = False


class PageFreeRecord(TraceRecord):
    def __init__(self, trace_id, trace_type, comm, pid, backtrace, addr, order):
        super().__init__(trace_id, trace_type, comm, pid, backtrace)
        self.addr = addr
        self.order = order
        self.is_pair = False


class GeneralSlabAllocRecord(TraceRecord):
    def __init__(self, trace_id, trace_type, comm, pid, backtrace, addr, slab, size, flags):
        super().__init__(trace_id, trace_type, comm, pid, backtrace)
        self.addr = addr
        self.slab = slab
        self.size = size
        self.flags = flags
        self.is_pair = False


class GeneralSlabFreeRecord(TraceRecord):
    def __init__(self, trace_id, trace_type, comm, pid, backtrace, addr):
        super().__init__(trace_id, trace_type, comm, pid, backtrace)
        self.addr = addr
        self.is_pair = False


class KmemCacheAllocRecord(TraceRecord):
    def __init__(self, trace_id, trace_type, comm, pid, backtrace, addr, slab, size, flags):
        super().__init__(trace_id, trace_type, comm, pid, backtrace)
        self.addr = addr
        self.slab = slab
        self.size = size
        self.flags = flags
        self.is_pair = False


class KmemCacheFreeRecord(TraceRecord):
    def __init__(self, trace_id, trace_type, comm, pid, backtrace, addr, slab):
        super().__init__(trace_id, trace_type, comm, pid, backtrace)
        self.addr = addr
        self.slab = slab
        self.is_pair = False


class CapCheckRecord(TraceRecord):
    pass


class SyscallEntryRecord(TraceRecord):
    pass

# Trace records


class TraceRecords:
    def __init__(self):
        self.orphan_records = []  # TODO: every type of record should have its own orphan_records
        self.page_record_pairs = []
        self.general_slab_record_pairs = []
        self.kmem_cache_record_pairs = []
        self.cap_check_records = []
        self.syscall_records = []

    def pair_type(self, trace_type):
        if trace_type == BackTraceType.PAGE_ALLOC:
            return BackTraceType.PAGE_FREE
        elif trace_type == BackTraceType.GENERAL_SLAB_ALLOC:
            return BackTraceType.GENERAL_SLAB_FREE
        elif trace_type == BackTraceType.KMEM_CACHE_ALLOC:
            return BackTraceType.KMEM_CACHE_FREE
        elif trace_type == BackTraceType.PAGE_FREE:
            return BackTraceType.PAGE_ALLOC
        elif trace_type == BackTraceType.GENERAL_SLAB_FREE:
            return BackTraceType.GENERAL_SLAB_ALLOC
        elif trace_type == BackTraceType.KMEM_CACHE_FREE:
            return BackTraceType.KMEM_CACHE_ALLOC
        else:
            print("Error: unknown trace type")
            return None

    def add_record(self, record: TraceRecord):
        if record.trace_type in [BackTraceType.PAGE_ALLOC, BackTraceType.GENERAL_SLAB_ALLOC, BackTraceType.KMEM_CACHE_ALLOC]:
            self.orphan_records.append(record)
        elif record.trace_type in [BackTraceType.PAGE_FREE, BackTraceType.GENERAL_SLAB_FREE, BackTraceType.KMEM_CACHE_FREE]:
            if len(self.orphan_records) == 0:
                print("Error: orphan_records is empty")
                return
            if not hasattr(record, "is_pair"):
                print("Error: record does not have is_pair attribute")
                return
            if not hasattr(record, "addr"):
                print("Error: record does not have addr attribute")
                return

            pair_candidate = [r for r in self.orphan_records if r.addr ==
                              record.addr and r.is_pair == False and r.trace_type == self.pair_type(record.trace_type)]

            if len(pair_candidate) == 0:
                print("Error: cannot find pair for record")
                print("orphan_counts: ", len(self.orphan_records))
                print("page_pair_counts: ", len(self.page_record_pairs))
                print("general_slab_pair_counts: ", len(self.general_slab_record_pairs))
                print("kmem_cache_pair_counts: ", len(self.kmem_cache_record_pairs))
                return

            if len(pair_candidate) > 1:
                print("Warning: multiple pairs found for record")
                for r in pair_candidate:
                    print(r.to_json())
                return

            pair = max(pair_candidate, key=lambda r: int(
                r.trace_id[ID_PREFIX_LEN:]))

            self.orphan_records.remove(pair)
            record.is_pair = True
            pair.is_pair = True
            if record.trace_type == BackTraceType.PAGE_FREE:
                self.page_record_pairs.append((pair, record))
            elif record.trace_type == BackTraceType.GENERAL_SLAB_FREE:
                self.general_slab_record_pairs.append((pair, record))
            elif record.trace_type == BackTraceType.KMEM_CACHE_FREE:
                self.kmem_cache_record_pairs.append((pair, record))
            else:
                print("Error: unknown trace type")
                return
        elif record.trace_type == BackTraceType.CAP_CHECK:
            self.cap_check_records.append(record)
        elif record.trace_type in [BackTraceType.SYSCALL_ENTRY, BackTraceType.SYSCALL_RETURN]:
            self.syscall_records.append(record)
        else:
            print("Error: unknown trace type")
            return

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

# Tracing Pointers


class PageAllocPoint(gdb.Breakpoint):
    def stop(self):
        global trace_id
        global trace_records
        comm = gdb.parse_and_eval("$lx_current()->comm")
        if "syz-executor" not in comm.string():
            return False
        backtrace = gdb.execute("bt", to_string=True)
        if "allocate_slab" in backtrace:
            return False
        print("--------")
        trace_id += 1
        page = gdb.parse_and_eval("$rax")  # HACK
        trace_info = {
            "id": id_prefix + str(trace_id),
            "type": BackTraceType.PAGE_ALLOC,
            "comm": comm.string(),
            "pid": int(gdb.parse_and_eval("$lx_current()->pid")),
            "backtrace": backtrace,
            "addr": int(page_to_addr(page)),
            "order": int(gdb.parse_and_eval("$rbp"))  # HACK
        }
        page_alloc_record = PageAllocRecord(
            trace_info["id"], trace_info["type"], trace_info["comm"], trace_info["pid"], trace_info["backtrace"], trace_info["addr"], trace_info["order"])
        trace_records.add_record(page_alloc_record)
        pprint.pprint(trace_info)
        print("========")
        return False


class PageFreePoint(gdb.Breakpoint):
    def stop(self):
        global trace_id
        global trace_records
        comm = gdb.parse_and_eval("$lx_current()->comm")
        if "syz-executor" not in comm.string():
            return False
        print("--------")
        trace_id += 1
        page = int(gdb.parse_and_eval("page"))
        trace_info = {
            "id": id_prefix + str(trace_id),
            "type": BackTraceType.PAGE_FREE,
            "comm": comm.string(),
            "pid": int(gdb.parse_and_eval("$lx_current()->pid")),
            "backtrace": gdb.execute("bt", to_string=True),
            "addr": int(page_to_addr(page)),
            "order": int(gdb.parse_and_eval("order"))
        }
        page_free_record = PageFreeRecord(
            trace_info["id"], trace_info["type"], trace_info["comm"], trace_info["pid"], trace_info["backtrace"], trace_info["addr"], trace_info["order"])
        trace_records.add_record(page_free_record)
        pprint.pprint(trace_info)
        print("========")
        return False


class GeneralSlabAllocPoint(gdb.Breakpoint):
    def stop(self):
        global trace_id
        global trace_records
        comm = gdb.parse_and_eval("$lx_current()->comm")
        if "syz-executor" not in comm.string():
            return False
        print("--------")
        trace_id += 1
        trace_info = {
            "id": id_prefix + str(trace_id),
            "type": BackTraceType.GENERAL_SLAB_ALLOC,
            "comm": comm.string(),
            "pid": int(gdb.parse_and_eval("$lx_current()->pid")),
            "backtrace": gdb.execute("bt", to_string=True),
            "addr": int(gdb.parse_and_eval("$rsi")),  # HACK
            "slab": gdb.parse_and_eval("((struct kmem_cache *)$rdi)->name").string(),  # HACK
            "size": int(gdb.parse_and_eval("$rdx")),  # HACK
            "flags": int(gdb.parse_and_eval("$rcx"))  # HACK
        }
        general_slab_alloc_record = GeneralSlabAllocRecord(trace_info["id"], trace_info["type"], trace_info["comm"], trace_info["pid"],
                                                           trace_info["backtrace"], trace_info["addr"], trace_info["slab"], trace_info["size"], trace_info["flags"])
        trace_records.add_record(general_slab_alloc_record)
        pprint.pprint(trace_info)
        print("========")
        return False


class GeneralSlabFreePoint(gdb.Breakpoint):
    def stop(self):
        global trace_id
        global trace_records
        comm = gdb.parse_and_eval("$lx_current()->comm")
        if "syz-executor" not in comm.string():
            return False
        print("--------")
        trace_id += 1
        trace_info = {
            "id": id_prefix + str(trace_id),
            "type": BackTraceType.GENERAL_SLAB_ALLOC,
            "comm": comm.string(),
            "pid": int(gdb.parse_and_eval("$lx_current()->pid")),
            "backtrace": gdb.execute("bt", to_string=True),
            "addr": int(gdb.parse_and_eval("object"))
        }
        general_slab_free_record = GeneralSlabFreeRecord(
            trace_info["id"], trace_info["type"], trace_info["comm"], trace_info["pid"], trace_info["backtrace"], trace_info["addr"])
        trace_records.add_record(general_slab_free_record)
        pprint.pprint(trace_info)
        print("========")
        return False


class KmemCacheAllocPoint(gdb.Breakpoint):
    def stop(self):
        global trace_id
        global trace_records
        comm = gdb.parse_and_eval("$lx_current()->comm")
        if "syz-executor" not in comm.string():
            return False
        print("--------")
        trace_id += 1
        trace_info = {
            "id": id_prefix + str(trace_id),
            "type": BackTraceType.KMEM_CACHE_ALLOC,
            "comm": comm.string(),
            "pid": int(gdb.parse_and_eval("$lx_current()->pid")),
            "backtrace": gdb.execute("bt", to_string=True),
            "addr": int(gdb.parse_and_eval("$r14")),  # HACK
            "slab": gdb.parse_and_eval("s->name").string(),
            "size": int(gdb.parse_and_eval("s->size")),
            "flags": int(gdb.parse_and_eval("gfpflags"))
        }
        kmem_cache_alloc_record = KmemCacheAllocRecord(
            trace_info["id"], trace_info["type"], trace_info["comm"], trace_info["pid"], trace_info["backtrace"], trace_info["addr"], trace_info["slab"], trace_info["size"], trace_info["flags"])
        trace_records.add_record(kmem_cache_alloc_record)
        pprint.pprint(trace_info)
        print("========")
        return False


class KmemCacheFreePoint(gdb.Breakpoint):
    def stop(self):
        global trace_id
        comm = gdb.parse_and_eval("$lx_current()->comm")
        if "syz-executor" not in comm.string():
            return False
        print("--------")
        trace_id += 1
        trace_info = {
            "id": id_prefix + str(trace_id),
            "type": BackTraceType.KMEM_CACHE_FREE,
            "comm": comm.string(),
            "pid": int(gdb.parse_and_eval("$lx_current()->pid")),
            "backtrace": gdb.execute("bt", to_string=True),
            "addr": int(gdb.parse_and_eval("x")),
            "slab": gdb.parse_and_eval("s->name").string(),
        }
        kmem_cache_free_record = KmemCacheFreeRecord(
            trace_info["id"], trace_info["type"], trace_info["comm"], trace_info["pid"], trace_info["backtrace"], trace_info["addr"], trace_info["slab"])
        trace_records.add_record(kmem_cache_free_record)
        pprint.pprint(trace_info)
        print("========")
        return False

# TODO: add more breakpoints for other types of backtrace


def page_to_addr(page):
    return direct_map_base + (page - vmemmap_base) * 0x40


trace_records = TraceRecords()

# Some magic here. Since syzkaller need rpc to communicate with the target machine,
# we need to delay the interrupt to make sure the rpc is established. Otherwise,
# the syzkaller will not be able to receive the response from the target machine.


def delayed_interrupt():
    time.sleep(20)
    gdb.execute('interrupt')


gdb.post_event(delayed_interrupt)
gdb.execute('continue')


time.sleep(2)

# BREAK at returning of __alloc_pages
# 0xffffffff816dba0f <__alloc_pages+527>:      ret
# 0xffffffff816dba05 <__alloc_pages+517>:      pop    rbx
page_alloc_breakpoint = PageAllocPoint("*0xffffffff816dba05")  # NOTE: DONE

# BREAK at beginning of free_pages_prepare
page_free_breakpoint = PageFreePoint("free_pages_prepare")  # NOTE: DONE

# BREAK at returning of kmem_cache_alloc
# 0xffffffff81745960 <kmem_cache_alloc_lru+256>:       ret
# 0xffffffff8174594f <kmem_cache_alloc_lru+239>:       add    rsp,0x8
kmem_cache_alloc_breakpoint_1 = KmemCacheAllocPoint(
    "*0xffffffff8174594f")  # NOTE: DONE
# 0xffffffff81745b90 <kmem_cache_alloc+256>:   ret
# 0xffffffff81745b7f <kmem_cache_alloc+239>:   add    rsp,0x8
kmem_cache_alloc_breakpoint_2 = KmemCacheAllocPoint("*0xffffffff81745b7f")

# BREAK at beginning of kmem_cache_free
kmem_cache_free_breakpoint = KmemCacheFreePoint(
    "kmem_cache_free")  # NOTE: DONE

# BREAK at returning of __do_kmalloc_node
# 0xffffffff8162615f <__kmalloc_node_track_caller+111>:        ret
# 0xffffffff81626145 <__kmalloc_node_track_caller+85>: call   0xffffffff81748990 <__kasan_kmalloc>
general_slab_alloc_breakpoint_1 = GeneralSlabAllocPoint(
    "*0xffffffff81626145")  # NOTE: DONE
# 0xffffffff816262d1 <__kmalloc_node+113>:     ret
# 0xffffffff816262b7 <__kmalloc_node+87>:      call   0xffffffff81748990 <__kasan_kmalloc>
general_slab_alloc_breakpoint_2 = GeneralSlabAllocPoint("*0xffffffff816262b7")
# 0xffffffff8162643c <__kmalloc+108>:  ret
# 0xffffffff81626424 <__kmalloc+84>:   call   0xffffffff81748990 <__kasan_kmalloc>
general_slab_alloc_breakpoint_3 = GeneralSlabAllocPoint("*0xffffffff81626424")
# 0xffffffff81625be5 <kmalloc_trace+69>:       jmp    0xffffffff81748990 <__kasan_kmalloc>
general_slab_alloc_breakpoint_4 = GeneralSlabAllocPoint("*0xffffffff81625be5")
# 0xffffffff81625c94 <kmalloc_node_trace+68>:  jmp    0xffffffff81748990 <__kasan_kmalloc>
general_slab_alloc_breakpoint_5 = GeneralSlabAllocPoint("*0xffffffff81625c94")

# BREAK at beginning of kfree
general_slab_free_breakpoint = GeneralSlabFreePoint("kfree")  # NOTE: DONE

gdb.execute('continue')

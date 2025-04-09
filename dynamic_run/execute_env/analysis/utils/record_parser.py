import re
import sys
import os
import hashlib
import json
import csv
import enum

from abc import ABC, abstractmethod
from pprint import pprint


class BackTraceType(enum.Enum):
    UNKNOWN = 0
    PAGE_ALLOC = 1
    PAGE_FREE = 2
    GENERAL_SLAB_ALLOC = 3
    GENERAL_SLAB_FREE = 4
    KMEM_CACHE_ALLOC = 5
    KMEM_CACHE_FREE = 6
    # CAP_CHECK = 7
    SYSCALL_ENTRY = 8
    SYSCALL_RETURN = 9
    KFREE_RCU = 10
    CALL_RCU = 11  # NOTE: Some of call_rcu are not kfree related


class Identity:
    def __init__(self, file, identity):
        self.record_file = file
        self.id = identity

    def __str__(self):
        return f"{self.record_file}:{self.id}"


class Record:
    class RecordError(Exception):
        def __init__(self, msg, backtrace=None):
            self.msg = msg
            self.backtrace = backtrace

        def __str__(self):
            return f"{self.msg}\nBACKTRACE:\n{self.backtrace}"

    type = BackTraceType.UNKNOWN

    def __init__(self, identity=None, backtrace_text=None):
        self.identity = identity
        self.backtrace = backtrace_text

    @abstractmethod
    def parse_backtrace(self):
        pass

    def error_during_parsing(self):
        raise self.RecordError("Error during parsing backtrace", self.backtrace)


class PageAllocRecord(Record):
    def __init__(self, identity=None, backtrace_text=None):
        super().__init__(identity, backtrace_text)
        self.type = BackTraceType.PAGE_ALLOC

        self.parse_backtrace()

    def parse_backtrace(self):
        pattern = r"BACK_TRACE_ALLOC_PAGES_START\norder: (\d+), alloc_flags: (0x[0-9a-fA-F]+), alloc_gfp: (0x[0-9a-fA-F]+)\naddr: (0x[0-9a-fA-F]+)\npid: (\d+), comm: (.*?)(?=, tgid), tgid: (\d+)\nRecorded capabilities:(.*?)(?=\nDumping stack:)\nDumping stack:(.*?)(?=\n\n|$)"

        m = re.search(pattern, self.backtrace, re.S)

        if m:
            self.order = int(m.group(1))
            self.alloc_flags = int(m.group(2), 16)
            self.alloc_gfp = int(m.group(3), 16)
            self.addr = int(m.group(4), 16)
            self.pid = int(m.group(5))
            self.comm = m.group(6).strip()
            self.tgid = int(m.group(7))
            self.caps = [i.strip() for i in m.group(8).strip().split("\n") if i]
            self.stack_trace = [i.strip() for i in m.group(9).strip().split("\n") if i]
        else:
            self.error_during_parsing()


class PageFreeRecord(Record):
    def __init__(self, identity=None, backtrace_text=None):
        super().__init__(identity, backtrace_text)
        self.type = BackTraceType.PAGE_FREE

        self.parse_backtrace()

    def parse_backtrace(self):
        pattern = r"BACK_TRACE_FREE_PAGE_START\naddr: (0x[0-9a-fA-F]+)\npid: (\d+), comm: (.*?)(?=, tgid), tgid: (\d+)\nRecorded capabilities:(.*?)(?=\nDumping stack:)\nDumping stack:(.*?)(?=\n\n|$)"

        m = re.search(pattern, self.backtrace, re.S)

        if m:
            self.addr = int(m.group(1), 16)
            self.pid = int(m.group(2))
            self.comm = m.group(3).strip()
            self.tgid = int(m.group(4))
            self.caps = [i.strip() for i in m.group(5).strip().split("\n") if i]
            self.stack_trace = [i.strip() for i in m.group(6).strip().split("\n") if i]
        else:
            self.error_during_parsing()


class GeneralSlabAllocRecord(Record):
    def __init__(self, identity=None, backtrace_text=None):
        super().__init__(identity, backtrace_text)
        self.type = BackTraceType.GENERAL_SLAB_ALLOC

        self.parse_backtrace()

    def parse_backtrace(self):
        pattern = r"BACK_TRACE_KMALLOC_START\nsize: (0x[0-9a-fA-F]+), flags: (0x[0-9a-fA-F]+), page_size: (0x[0-9a-fA-F]+)\naddr: (0x[0-9a-fA-F]+)\npid: (\d+), comm: (.*?)(?=, tgid), tgid: (\d+)\nRecorded capabilities:(.*?)(?=\nDumping stack:)\nDumping stack:(.*?)(?=\n\n|$)"

        m = re.search(pattern, self.backtrace, re.S)

        if m:
            self.size = int(m.group(1), 16)
            self.flags = int(m.group(2), 16)
            self.page_size = int(m.group(3), 16)
            self.addr = int(m.group(4), 16)
            self.pid = int(m.group(5))
            self.comm = m.group(6).strip()
            self.tgid = int(m.group(7))
            self.caps = [i.strip() for i in m.group(8).strip().split("\n") if i]
            self.stack_trace = [i.strip() for i in m.group(9).strip().split("\n") if i]
        else:
            self.error_during_parsing()


class GeneralSlabFreeRecord(Record):
    def __init__(self, identity=None, backtrace_text=None):
        super().__init__(identity, backtrace_text)
        self.type = BackTraceType.GENERAL_SLAB_FREE

        self.parse_backtrace()

    def parse_backtrace(self):
        pattern = r"BACK_TRACE_KFREE_START\naddr: (0x[0-9a-fA-F]+)\n(.*?)(?=\npid:)\npid: (\d+), comm: (.*?)(?=, tgid), tgid: (\d+)\nRecorded capabilities:(.*?)(?=\nDumping stack:)\nDumping stack:(.*?)(?=\n\n|$)"

        m = re.search(pattern, self.backtrace, re.S)

        if m:
            self.addr = int(m.group(1), 16)
            m2 = m.group(2)
            if m2.startswith("s: "):
                self.slab = m2[3:].strip()
            elif m2 == "free large kmalloc object":
                self.slab = "LARGE"
            else:
                self.error_during_parsing()
            self.pid = int(m.group(3))
            self.comm = m.group(4).strip()
            self.tgid = int(m.group(5))
            self.caps = [i.strip() for i in m.group(6).strip().split("\n") if i]
            self.stack_trace = [i.strip() for i in m.group(7).strip().split("\n") if i]
        else:
            self.error_during_parsing()


class KmemCacheAllocRecord(Record):
    def __init__(self, identity=None, backtrace_text=None):
        super().__init__(identity, backtrace_text)
        self.type = BackTraceType.KMEM_CACHE_ALLOC

        self.parse_backtrace()

    def parse_backtrace(self):
        pattern = r"BACK_TRACE_KMEM_CACHE_ALLOC_START\ns: (.*?), flags: (0x[0-9a-fA-F]+), page_size: (0x[0-9a-fA-F]+)\naddr: (0x[0-9a-fA-F]+)\npid: (\d+), comm: (.*?)(?=, tgid), tgid: (\d+)\nRecorded capabilities:(.*?)(?=\nDumping stack:)\nDumping stack:(.*?)(?=\n\n|$)"

        m = re.search(pattern, self.backtrace, re.S)

        if m:
            self.s = m.group(1).strip()
            self.flags = int(m.group(2), 16)
            self.page_size = int(m.group(3), 16)
            self.addr = int(m.group(4), 16)
            self.pid = int(m.group(5))
            self.comm = m.group(6).strip()
            self.tgid = int(m.group(7))
            self.caps = [i.strip() for i in m.group(8).strip().split("\n") if i]
            self.stack_trace = [i.strip() for i in m.group(9).strip().split("\n") if i]
        else:
            self.error_during_parsing()


class KmemCacheFreeRecord(Record):
    def __init__(self, identity=None, backtrace_text=None):
        super().__init__(identity, backtrace_text)
        self.type = BackTraceType.KMEM_CACHE_FREE

        self.parse_backtrace()

    def parse_backtrace(self):
        pattern = r"BACK_TRACE_KMEM_CACHE_FREE_START\naddr: (0x[0-9a-fA-F]+)\ns: (.*?)(?=\npid:)\npid: (\d+), comm: (.*?)(?=, tgid), tgid: (\d+)\nRecorded capabilities:(.*?)(?=\nDumping stack:)\nDumping stack:(.*?)(?=\n\n|$)"

        m = re.search(pattern, self.backtrace, re.S)

        if m:
            self.addr = int(m.group(1), 16)
            self.slab = m.group(2).strip()
            self.pid = int(m.group(3))
            self.comm = m.group(4).strip()
            self.tgid = int(m.group(5))
            self.caps = [i.strip() for i in m.group(6).strip().split("\n") if i]
            self.stack_trace = [i.strip() for i in m.group(7).strip().split("\n") if i]
        else:
            self.error_during_parsing()


class SyscallEntryRecord(Record):
    def __init__(self, identity=None, backtrace_text=None):
        super().__init__(identity, backtrace_text)
        self.type = BackTraceType.SYSCALL_ENTRY

        self.parse_backtrace()

    def parse_backtrace(self):
        pattern = r"BACK_TRACE_SYSCALL_ENTRY\nsyscall\(NR=(\d+),\s(0x[0-9a-fA-F]+),\s(0x[0-9a-fA-F]+),\s(0x[0-9a-fA-F]+),\s(0x[0-9a-fA-F]+),\s(0x[0-9a-fA-F]+),\s(0x[0-9a-fA-F]+)\)\npid: (\d+), comm: (.*?)(?=, tgid), tgid: (\d+)(?=\n\n|$)"

        m = re.search(pattern, self.backtrace, re.S)

        if m:
            self.syscall_nr = int(m.group(1))
            self.args = [int(i, 16) for i in m.group(2, 3, 4, 5, 6, 7)]
            self.pid = int(m.group(8))
            self.comm = m.group(9).strip()
            self.tgid = int(m.group(10))
        else:
            self.error_during_parsing()


class SyscallReturnRecord(Record):
    def __init__(self, identity=None, backtrace_text=None):
        super().__init__(identity, backtrace_text)
        self.type = BackTraceType.SYSCALL_RETURN

        self.parse_backtrace()

    def parse_backtrace(self):
        pattern = r"BACK_TRACE_SYSCALL_RETURN\npid: (\d+), comm: (.*?)(?=, tgid), tgid: (\d+)(?=\n\n|$)"

        m = re.search(pattern, self.backtrace, re.S)

        if m:
            self.pid = int(m.group(1))
            self.comm = m.group(2).strip()
            self.tgid = int(m.group(3))
        else:
            self.error_during_parsing()


class KfreeRcuRecord(Record):
    def __init__(self, identity=None, backtrace_text=None):
        super().__init__(identity, backtrace_text)
        self.type = BackTraceType.KFREE_RCU

        self.parse_backtrace()

    def parse_backtrace(self):
        pattern = r"BACK_TRACE_KFREE_RCU_START\nptr: (0x[0-9a-fA-F]+)\npid: (\d+), comm: (.*?)(?=, tgid), tgid: (\d+)\nRecorded capabilities:(.*?)(?=\nDumping stack:)\nDumping stack:(.*?)(?=\n\n|$)"

        m = re.search(pattern, self.backtrace, re.S)

        if m:
            self.addr = int(m.group(1), 16)
            self.pid = int(m.group(2))
            self.comm = m.group(3).strip()
            self.tgid = int(m.group(4))
            self.caps = [i.strip() for i in m.group(5).strip().split("\n") if i]
            self.stack_trace = [i.strip() for i in m.group(6).strip().split("\n") if i]
        else:
            self.error_during_parsing()


class CallRcuRecord(Record):
    def __init__(self, identity=None, backtrace_text=None):
        super().__init__(identity, backtrace_text)
        self.type = BackTraceType.CALL_RCU

        self.parse_backtrace()

    def parse_backtrace(self):
        pattern = r"BACK_TRACE_CALL_RCU_START\nhead: (0x[0-9a-fA-F]+), func: (0x[0-9a-fA-F]+)\npid: (\d+), comm: (.*?)(?=, tgid), tgid: (\d+)\nRecorded capabilities:(.*?)(?=\nDumping stack:)\nDumping stack:(.*?)(?=\n\n|$)"

        m = re.search(pattern, self.backtrace, re.S)

        if m:
            self.head = int(m.group(1), 16)
            self.func = int(m.group(2), 16)
            self.pid = int(m.group(3))
            self.comm = m.group(4).strip()
            self.tgid = int(m.group(5))
            self.caps = [i.strip() for i in m.group(6).strip().split("\n") if i]
            self.stack_trace = [i.strip() for i in m.group(7).strip().split("\n") if i]
        else:
            self.error_during_parsing()


def do_test(path):
    file = os.path.basename(path)
    with open(path, "r") as f:
        data = f.read()
    l_data = data.split("\n\n")
    l_data = [s for s in l_data if s]

    # for i in l_data:
    for i, backtrace_text in enumerate(l_data):
        if backtrace_text.startswith("BACK_TRACE_ALLOC_PAGES_START"):
            r = PageAllocRecord(Identity(file, i), backtrace_text)
        elif backtrace_text.startswith("BACK_TRACE_FREE_PAGE_START"):
            r = PageFreeRecord(Identity(file, i), backtrace_text)
        elif backtrace_text.startswith("BACK_TRACE_KMALLOC_START"):
            r = GeneralSlabAllocRecord(Identity(file, i), backtrace_text)
        elif backtrace_text.startswith("BACK_TRACE_KFREE_START"):
            r = GeneralSlabFreeRecord(Identity(file, i), backtrace_text)
        elif backtrace_text.startswith("BACK_TRACE_KMEM_CACHE_ALLOC_START"):
            r = KmemCacheAllocRecord(Identity(file, i), backtrace_text)
        elif backtrace_text.startswith("BACK_TRACE_KMEM_CACHE_FREE_START"):
            r = KmemCacheFreeRecord(Identity(file, i), backtrace_text)
        elif backtrace_text.startswith("BACK_TRACE_SYSCALL_ENTRY"):
            r = SyscallEntryRecord(Identity(file, i), backtrace_text)
        elif backtrace_text.startswith("BACK_TRACE_SYSCALL_RETURN"):
            r = SyscallReturnRecord(Identity(file, i), backtrace_text)
        elif backtrace_text.startswith("BACK_TRACE_KFREE_RCU_START"):
            r = KfreeRcuRecord(Identity(file, i), backtrace_text)
        elif backtrace_text.startswith("BACK_TRACE_CALL_RCU_START"):
            r = CallRcuRecord(Identity(file, i), backtrace_text)
        else:
            print("Error: Unknown record type")
            print()
            sys.exit(-1)


if __name__ == "__main__":
    do_test(sys.argv[1])

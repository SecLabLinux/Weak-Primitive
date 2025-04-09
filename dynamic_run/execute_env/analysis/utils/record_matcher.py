import sys
import os
import json
import time

from typing import List, Dict, Tuple, Optional
from abc import ABC, abstractmethod
from pprint import pprint

from utils.record_parser import (
    Record,
    Identity,
    BackTraceType,
    PageAllocRecord,
    PageFreeRecord,
    GeneralSlabAllocRecord,
    GeneralSlabFreeRecord,
    KmemCacheAllocRecord,
    KmemCacheFreeRecord,
    SyscallEntryRecord,
    SyscallReturnRecord,
    KfreeRcuRecord,
    CallRcuRecord,
)
from utils.record_json import RecordEncoder

"""
Match coresponding record of alloc and free in a record file.
Match Strategy:
1. Match the syscall enter/return records.
2. Find the alloc records during the syscall. (We just assume the alloc records are in the syscall)
3. Match the coresponing free records.
4. If a free record is in RCU context (softirq), find the corresponding call_rcu record.

# TODO: Find which syscall trigger the alloc/free.
"""


class MatchableRecord:
    def __init__(self, record: Record):
        if not isinstance(record, Record):
            raise TypeError("record must be an instance of Record")
        if record.type not in [
            BackTraceType.PAGE_ALLOC,
            BackTraceType.PAGE_FREE,
            BackTraceType.GENERAL_SLAB_ALLOC,
            BackTraceType.GENERAL_SLAB_FREE,
            BackTraceType.KMEM_CACHE_ALLOC,
            BackTraceType.KMEM_CACHE_FREE,
        ]:
            raise ValueError("record type must be a pairable type")
        self.record = record
        self.syscall_record = None
        self.is_duplicate = False
        self.duplicate_of = None

    def __getattr__(self, attr):
        return getattr(self.record, attr)


class RecordMatcher:
    def __init__(self, backtrace_record_path):
        self.backtrace_record_path = backtrace_record_path
        self.backtrace_record_file = os.path.basename(backtrace_record_path)
        # all records
        self.record_list = []
        # unsored orphan records / records without pair
        self.matchable_record_list = []
        # paired page alloc/free records
        self.paired_page_alloc_record_list = []
        # paired general slab alloc/free records
        self.paired_general_slab_alloc_record_list = []
        # paired kmem cache alloc/free records
        self.paired_kmem_cache_alloc_record_list = []
        # paired syscall entry/return records
        self.orphan_record_list = []

        self.parse_file()

    def parse_file(self):
        file = self.backtrace_record_file
        with open(self.backtrace_record_path, "r") as f:
            data = f.read()
        l_data = data.split("\n\n")
        l_data = [s for s in l_data if s]

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

            self.record_list.append(r)

    def match(self):
        print("Matching syscall...")
        start_time = time.time()
        self.match_syscall()
        print(f"Matching syscall takes {time.time() - start_time} seconds")
        print("Matching free...")
        start_time = time.time()
        self.match_free()
        print(f"Matching free takes {time.time() - start_time} seconds")
        print("Matching duplicate...")
        start_time = time.time()
        self.match_duplicate()
        print(f"Matching duplicate takes {time.time() - start_time} seconds")

    def match_syscall(self):
        # during_syscall = False
        current_syscall_record = None
        for i, r in enumerate(self.record_list):
            if r.type == BackTraceType.SYSCALL_ENTRY:
                if not r.comm.startswith("syz-executor"):
                    raise ValueError(
                        f"syscall entry record comm is not syz-executor\n{r.to_dict}"
                    )
                # during_syscall = True
                current_syscall_record = r
            elif r.type == BackTraceType.SYSCALL_RETURN:
                if not r.comm.startswith("syz-executor"):
                    raise ValueError(
                        f"syscall return record comm is not syz-executor\n{r.to_dict}"
                    )
                # during_syscall = False
                current_syscall_record = None
            elif current_syscall_record is not None:
                if r.type in [
                    BackTraceType.PAGE_ALLOC,
                    BackTraceType.GENERAL_SLAB_ALLOC,
                    BackTraceType.KMEM_CACHE_ALLOC,
                ]:
                    mtr = MatchableRecord(r)
                    mtr.syscall_record = current_syscall_record
                    self.matchable_record_list.append((i, mtr))

    def match_free(self):
        if not self.matchable_record_list:
            raise ValueError("matchable_record_list is empty")
        for i, r in self.matchable_record_list:
            if r.type == BackTraceType.PAGE_ALLOC:
                # find the corresponding free record
                for j in range(i + 1, len(self.record_list)):
                    if self.record_list[j].type == BackTraceType.PAGE_FREE:
                        if self.record_list[j].addr == r.addr:
                            self.paired_page_alloc_record_list.append(
                                (r, self.record_list[j])
                            )
                            # print(json.dumps(r, indent=4, cls=RecordEncoder))
                            break
                    if self.record_list[j].type == BackTraceType.PAGE_ALLOC:
                        if self.record_list[j].addr == r.addr:
                            self.orphan_record_list.append(r)
                            break
                    if j == len(self.record_list) - 1:
                        self.orphan_record_list.append(r)
            elif r.type == BackTraceType.GENERAL_SLAB_ALLOC:
                for j in range(i + 1, len(self.record_list)):
                    if self.record_list[j].type == BackTraceType.GENERAL_SLAB_FREE:
                        if self.record_list[j].addr == r.addr:
                            self.paired_general_slab_alloc_record_list.append(
                                (r, self.record_list[j])
                            )
                            break
                    if self.record_list[j].type == BackTraceType.GENERAL_SLAB_ALLOC:
                        if self.record_list[j].addr == r.addr:
                            self.orphan_record_list.append(r)
                            break
                    if j == len(self.record_list) - 1:
                        self.orphan_record_list.append(r)
            elif r.type == BackTraceType.KMEM_CACHE_ALLOC:
                for j in range(i + 1, len(self.record_list)):
                    if self.record_list[j].type == BackTraceType.KMEM_CACHE_FREE:
                        if self.record_list[j].addr == r.addr:
                            self.paired_kmem_cache_alloc_record_list.append(
                                (r, self.record_list[j])
                            )
                            break
                    if self.record_list[j].type == BackTraceType.KMEM_CACHE_ALLOC:
                        if self.record_list[j].addr == r.addr:
                            self.orphan_record_list.append(r)
                            break
                    if j == len(self.record_list) - 1:
                        self.orphan_record_list.append(r)
            else:
                raise ValueError("record type is not matchable")

    def match_rcu(self):
        # TODO: RCU Match
        pass

    def match_duplicate(self):
        for i, rm in enumerate(self.orphan_record_list):
            if rm.is_duplicate:
                continue
            for j in range(i + 1, len(self.orphan_record_list)):
                if rm.stack_trace == self.orphan_record_list[j].stack_trace:
                    self.orphan_record_list[j].is_duplicate = True
                    self.orphan_record_list[j].duplicate_of = rm.identity
        for i, rm in enumerate(self.paired_page_alloc_record_list):
            if rm[0].is_duplicate:
                continue
            for j in range(i + 1, len(self.paired_page_alloc_record_list)):
                if (
                    rm[0].stack_trace
                    == self.paired_page_alloc_record_list[j][0].stack_trace
                ):
                    self.paired_page_alloc_record_list[j][0].is_duplicate = True
                    self.paired_page_alloc_record_list[j][1].is_duplicate = True
                    self.paired_page_alloc_record_list[j][0].duplicate_of = rm[
                        0
                    ].identity
                    self.paired_page_alloc_record_list[j][1].duplicate_of = rm[
                        1
                    ].identity
        for i, rm in enumerate(self.paired_general_slab_alloc_record_list):
            if rm[0].is_duplicate:
                continue
            for j in range(i + 1, len(self.paired_general_slab_alloc_record_list)):
                if (
                    rm[0].stack_trace
                    == self.paired_general_slab_alloc_record_list[j][0].stack_trace
                ):
                    self.paired_general_slab_alloc_record_list[j][0].is_duplicate = True
                    self.paired_general_slab_alloc_record_list[j][1].is_duplicate = True
                    self.paired_general_slab_alloc_record_list[j][0].duplicate_of = rm[
                        0
                    ].identity
                    self.paired_general_slab_alloc_record_list[j][1].duplicate_of = rm[
                        1
                    ].identity
        for i, rm in enumerate(self.paired_kmem_cache_alloc_record_list):
            if rm[0].is_duplicate:
                continue
            for j in range(i + 1, len(self.paired_kmem_cache_alloc_record_list)):
                if (
                    rm[0].stack_trace
                    == self.paired_kmem_cache_alloc_record_list[j][0].stack_trace
                ):
                    self.paired_kmem_cache_alloc_record_list[j][0].is_duplicate = True
                    self.paired_kmem_cache_alloc_record_list[j][1].is_duplicate = True
                    self.paired_kmem_cache_alloc_record_list[j][0].duplicate_of = rm[
                        0
                    ].identity
                    self.paired_kmem_cache_alloc_record_list[j][1].duplicate_of = rm[
                        1
                    ].identity


if __name__ == "__main__":
    rm = RecordMatcher(sys.argv[1])
    rm.match()
    print(f"total record: {len(rm.record_list)}")
    print(f"total matchable record: {len(rm.matchable_record_list)}")
    print(f"total orphan record: {len(rm.orphan_record_list)}")
    print(
        f"total paired page alloc/free record: {len(rm.paired_page_alloc_record_list)}"
    )
    print(
        f"total paired general slab alloc/free record: {len(rm.paired_general_slab_alloc_record_list)}"
    )
    print(
        f"total paired kmem cache alloc/free record: {len(rm.paired_kmem_cache_alloc_record_list)}"
    )
    print(
        f"unique orphan record: {len([r for r in rm.orphan_record_list if not r.is_duplicate])}"
    )
    print(
        f"unique paired page alloc/free record: {len([r for r in rm.paired_page_alloc_record_list if not r[0].is_duplicate])}"
    )
    print(
        f"unique paired general slab alloc/free record: {len([r for r in rm.paired_general_slab_alloc_record_list if not r[0].is_duplicate])}"
    )
    print(
        f"unique paired kmem cache alloc/free record: {len([r for r in rm.paired_kmem_cache_alloc_record_list if not r[0].is_duplicate])}"
    )
    print()

    with open("orphan_record_list.json", "w") as f:
        json.dump(rm.orphan_record_list, f, indent=4, cls=RecordEncoder)
    with open("paired_page_alloc_record_list.json", "w") as f:
        json.dump(rm.paired_page_alloc_record_list, f, indent=4, cls=RecordEncoder)
    with open("paired_general_slab_alloc_record_list.json", "w") as f:
        json.dump(
            rm.paired_general_slab_alloc_record_list, f, indent=4, cls=RecordEncoder
        )
    with open("paired_kmem_cache_alloc_record_list.json", "w") as f:
        json.dump(
            rm.paired_kmem_cache_alloc_record_list, f, indent=4, cls=RecordEncoder
        )

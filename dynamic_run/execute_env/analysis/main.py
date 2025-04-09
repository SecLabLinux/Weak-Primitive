import sys
import json
from utils.record_json import RecordEncoder
from utils.record_parser import Record, Identity, BackTraceType
from utils.record_matcher import MatchableRecord, RecordMatcher

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

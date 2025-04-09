import json
# import record_parser
# import record_matcher
import sys

class RecordEncoder(json.JSONEncoder):
    def default(self, obj):
        from utils.record_parser import Record, Identity, BackTraceType
        from utils.record_matcher import MatchableRecord
        if isinstance(obj, MatchableRecord):
            return obj.__dict__.copy()
        if isinstance(obj, Record):
            result = obj.__dict__.copy()  
            return result
        if isinstance(obj, Identity):
            result = obj.__dict__.copy()
            return result
        if isinstance(obj, BackTraceType):
            return obj.name
        return json.JSONEncoder.default(self, obj)
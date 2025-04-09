import re
import sys
import os
import hashlib
import json
import csv

from pprint import pprint


DEBUG = False

class Record:
    def __init__(self, trace_type, *args, **kwargs):
        self.type = trace_type

        if 'addr' in kwargs:
            self.addr = kwargs['addr']  # int64
        else:
            self.addr = None
        
        if 'caps' in kwargs:
            self.caps = kwargs['caps']  # string
        else:
            self.caps = None

        if 'stack_trace' in kwargs:
            self.stack_trace = kwargs['stack_trace']  # string
            md5 = hashlib.md5()
            md5.update(self.stack_trace.encode('utf-8'))
            self.stack_trace_hash = md5.hexdigest()
        else:
            self.stack_trace = None
            self.stack_trace_hash = None

        self.stack_trace_locations = self.trace_to_location()


    def do_record(self):
        global DEBUG
        if self.stack_trace_hash == None:
            return
        if self.stack_trace_hash not in stack_trace_hashes:
            if self.type == "kmalloc":
                self.object_type = self.get_kmalloc_object_type()
            stack_trace_hashes.add(self.stack_trace_hash)
            global_records.append(self)
        if DEBUG:
            print(self)

    def trace_to_location(self):
        if self.stack_trace == None:
            return []
        locations = []
        ### in_known_codeql_function = False
        for line in self.stack_trace.split("\n"):
            r = re.compile(r"^\s+([a-zA-Z_][0-9a-zA-Z_\.]*)\+(0x[0-9a-f]+)\/(0x[0-9a-f]+)$")
            m = r.match(line)
            function_name = m.group(1)
            offset = int(m.group(2),16)
            function_size = int(m.group(3),16)
            code_addr = get_symbol_address(function_name) + offset
            location = get_line(code_addr)
            # 为了效率，还是暂时不要了
            # src_code = []
            # for item in location:
            #     src_code.append(get_src_code(os.path.join("/home/v1me/workspace/challs/kernel_pwn_env/pwn/linux-6.2.6/", item["File"]), item["Line"]))
            # locations.append([line, function_name, code_addr, location, src_code])
            locations.append([line, function_name, code_addr, location])
            ### if self.type == "kmalloc":
            ###     call_sites = get_codeql_alloc_sites()
            ###     if function_name.split(".", 1)[0] in [x[1] for x in call_sites]:
            ###         in_known_codeql_function = True
        ### if self.type == "kmalloc" and in_known_codeql_function == False:
        ###     print(self.stack_trace)
        ### elif self.type == "kmalloc" and in_known_codeql_function == True:
        ###     print("ok")
        return locations

    def get_kmalloc_object_type(self):
        if self.stack_trace == None:
            return None
        if self.type != "kmalloc":
            return None
        if not self.stack_trace_locations:
            return None

        trace_functions = [function_name.split(".", 1)[0] for function_name in [x[1] for x in self.stack_trace_locations]]
        for i in range(len(trace_functions)-1):
            caller_callee_type_list = get_caller_callee_type() 
            caller_callee_type_list_noinline_check = get_caller_callee_type_noinline_check()
            for caller_callee_type in caller_callee_type_list:
                if caller_callee_type[0] == trace_functions[i+1] and caller_callee_type[1] == trace_functions[i]:
                    # if i != 1:
                        # print(trace_functions)
                    print("Found: ", caller_callee_type[2], " i: ", i, trace_functions)
                    return caller_callee_type[2]
        for i in range(len(trace_functions)-1):
            for caller_callee_type in caller_callee_type_list_noinline_check:
                if caller_callee_type[0] == trace_functions[i+1] and caller_callee_type[1] == trace_functions[i]:
                    # if i != 1:
                        # print(trace_functions)
                    print("Found No Inline: ", caller_callee_type[2], " i: ", i, trace_functions)
                    return caller_callee_type[2]
            

        # print(trace_functions)
        print("Not found", trace_functions)
        return None
            
    
    def __str__(self):
        return str(vars(self))

    def __repr__(self):
        return str(vars(self))


class FreePageRecord(Record):
    """
    addr = int(m.group(1),16)
    caps = m.group(2).split("\n")
    stack_trace = m.group(3)
    """
    def __init__(self, *args, **kwargs):
        super().__init__("free page", *args, **kwargs)


class AllocPageRecord(Record):
    """
    order = int(m.group(1))
    alloc_flags = int(m.group(2),16)
    alloc_gfp = int(m.group(3),16)
    addr = int(m.group(4),16)
    caps = m.group(5).split("\n")
    stack_trace = m.group(6)
    """
    def __init__(self, *args, **kwargs):
        super().__init__("alloc page", *args, **kwargs)
        if 'order' in kwargs:
            self.order = kwargs['order']
        else:
            self.order = None
        
        if 'alloc_flags' in kwargs:
            self.alloc_flags = kwargs['alloc_flags']
        else:
            self.alloc_flags = None
        
        if 'alloc_gfp' in kwargs:
            self.alloc_gfp = kwargs['alloc_gfp']
        else:
            self.alloc_gfp = None


class KmallocRecord(Record):
    """
    size = int(m.group(1),16)
    flags = int(m.group(2),16)
    page_size = int(m.group(3),16)
    addr = int(m.group(4),16)
    caps = m.group(5).split("\n")
    stack_trace = m.group(6)
    """
    def __init__(self, *args, **kwargs):
        super().__init__("kmalloc", *args, **kwargs)
        if 'size' in kwargs:
            self.size = kwargs['size']
        else:
            self.size = None
        
        if 'flags' in kwargs:
            self.flags = kwargs['flags']
        else:
            self.flags = None
        
        if 'page_size' in kwargs:
            self.page_size = kwargs['page_size']
        else:
            self.page_size = None


class KfreeRecord(Record):
    """
    addr = int(m.group(1),16)
    if m.group(2):
        slub = m.group(2)
    elif m.group(3):
        slub = "LARGE OBJECT"
    else:
        print("Error when parsing BACK_TRACE_KFREE_START", file=sys.stderr)
        if DEBUG:
            print("-----------------------")
            print(s)
            print("-----------------------")
        break
    caps = m.group(4).split("\n")
    stack_trace = m.group(5)
    """
    def __init__(self, *args, **kwargs):
        super().__init__("kfree", *args, **kwargs)
        if 'slub' in kwargs:
            self.slub = kwargs['slub']
        else:
            self.slub = None


class KmemCacheAllocRecord(Record):
    """
    slub = m.group(1)
    flags = int(m.group(2),16)
    page_size = int(m.group(3),16)
    addr = int(m.group(4),16)
    caps = m.group(5).split("\n")
    stack_trace = m.group(6)
    """
    def __init__(self, *args, **kwargs):
        super().__init__("kmem cache alloc", *args, **kwargs)
        if 'flags' in kwargs:
            self.flags = kwargs['flags']
        else:
            self.flags = None

        if 'page_size' in kwargs:
            self.page_size = kwargs['page_size']
        else:
            self.page_size = None

        if 'slub' in kwargs:
            self.slub = kwargs['slub']
        else:
            self.slub = None


class KmemCacheFreeRecord(Record):
    """
    addr = int(m.group(1),16)
    slub = m.group(2)
    caps = m.group(3).split("\n")
    stack_trace = m.group(4) 
    """
    def __init__(self, *args, **kwargs):
        super().__init__("kmem cache free", *args, **kwargs)
        if 'slub' in kwargs:
            self.slub = kwargs['slub']
        else:
            self.slub = None



stack_trace_hashes = set()
global_records = []

symbols = {}
address_to_location = {}

codeql_alloc_functions = []
codeql_alloc_sites = []

caller_callee_type = []
caller_callee_type_noinline_check = []

# TODO
def get_caller_callee_type():
    if not caller_callee_type:
        with open("function_type_4.csv", "r") as f:
            csv_reader = csv.reader(f, delimiter=',', quotechar='"')
            for row in csv_reader:
                if len(row) == 5:
                    caller_callee_type.append([row[0], row[1], row[3]])
    return caller_callee_type

def get_caller_callee_type_noinline_check():
    if not caller_callee_type_noinline_check:
        with open("function_type_noinline_check.csv", "r") as f:
            csv_reader = csv.reader(f, delimiter=',', quotechar='"')
            for row in csv_reader:
                if len(row) == 5:
                    caller_callee_type_noinline_check.append([row[0], row[1], row[3]])
    return caller_callee_type_noinline_check

def get_codeql_alloc_functions():
    if not codeql_alloc_functions:
        with open("alloc_functions.txt", "r") as f:
            for line in f:
                codeql_alloc_functions.append(line.strip())
    return codeql_alloc_functions

def get_codeql_alloc_sites():
    if not codeql_alloc_sites:
        with open("alloc_sites.txt", "r") as f:
            # example:
            # "kzalloc_node","svc_rqst_alloc","svc_rqst *","file:///home/v1me/workspace/linux_build_test/linux-6.2.6/net/sunrpc/svc.c:636:10:636:21"
            csv_reader = csv.reader(f, delimiter=',', quotechar='"')
            for row in csv_reader:
                if len(row) == 4:
                    codeql_alloc_sites.append(row)
    return codeql_alloc_sites

def get_src_code(file, line):
    with open(file, "r") as f:
        lines = f.readlines()
        if line > len(lines):
            # this may happen
            ret = ""
        elif line > 1 and line < len(lines):
            ret = lines[line-2].strip() + "\n" + lines[line-1].strip() + "\n" + lines[line].strip()
        elif line == 1 and line < len(lines):
            ret = lines[line-1].strip() + "\n" + lines[line].strip()
        elif line > 1 and line == len(lines):
            ret = lines[line-2].strip() + "\n" + lines[line-1].strip()
        else:
            ret = lines[line-1].strip()
        return ret

def get_symbol_address(symbol_name):
    if not symbols:
        with open("System.map", "r") as f:
            for line in f:
                addr, _, name = line.split()
                symbols[name] = int(addr,16)
    return symbols[symbol_name]

def get_line(addr):
    if not address_to_location:
        with open("dwarf_address_location.json", "r") as f:
            address_location_list = json.load(f)
            for item in address_location_list:
                if int(item["Address"], 16) not in address_to_location: 
                    address_to_location[int(item["Address"], 16)] = [] 
                address_to_location[int(item["Address"], 16)].append({"File": item["File"], "Line": item["Line"]})
    if addr in address_to_location:
        return address_to_location[addr]
    else:
        return []

def get_sections(data):
    delims = [
                "BACK_TRACE_FREE_PAGE_START",
                "BACK_TRACE_ALLOC_PAGES_START",
                "BACK_TRACE_KMALLOC_START",
                "BACK_TRACE_KFREE_START",
                "BACK_TRACE_KMEM_CACHE_ALLOC_START",
                "BACK_TRACE_KMEM_CACHE_FREE_START"
             ]
    pattern = '(' + '|'.join([re.escape(x)+'.*?' for x in delims]) + ')(?=' + '|'.join(map(re.escape, delims)) + '|$)'
    result = re.findall(pattern, data, re.DOTALL)
    if DEBUG:
        print("records in the file: ", len(result))
    return result

def parse_data_file(filename):
    with open(filename, "r") as f:
        data = f.read()

    sections = get_sections(data)
    for s in sections:
        if s.count("do_back_trace_record+") > 1:
            print("Warning: do_back_trace_record+ is more than once", file=sys.stderr)
            if DEBUG:
                print("-----------------------")
                print(s)
                print("-----------------------")
            continue
        if "BACK_TRACE_FREE_PAGE_START" in s:
            r = re.compile("^BACK_TRACE_FREE_PAGE_START\n"
                           "addr: (0x[0-9a-f]+)\n\n"
                           "Recorded capabilities: \n(.*?)"
                           "Dumping stack: \n(.*?)$", re.DOTALL)
            m = r.match(s)
            if not m:
                print("Error when parsing BACK_TRACE_FREE_PAGE_START", file=sys.stderr)
                if DEBUG:
                    print("-----------------------")
                    print(s)
                    print("-----------------------")
                break

            addr = int(m.group(1),16)
            caps = m.group(2).split("\n")
            stack_trace = m.group(3)

            free_page_record = FreePageRecord(addr=addr, caps=caps, stack_trace=stack_trace)
            free_page_record.do_record()

        elif "BACK_TRACE_ALLOC_PAGES_START" in s:
            r = re.compile("^BACK_TRACE_ALLOC_PAGES_START\n"
                           "order: ([0-9]+), alloc_flags: (0x[0-9a-f]+), alloc_gfp: (0x[0-9a-f]+)\n"
                           "addr: (0x[0-9a-f]+)\n\n"
                           "Recorded capabilities: \n(.*?)"
                           "Dumping stack: \n(.*?)$", re.DOTALL)
            m = r.match(s)
            if not m:
                print("Error when parsing BACK_TRACE_ALLOC_PAGES_START", file=sys.stderr)
                if DEBUG:
                    print("-----------------------")
                    print(s)
                    print("-----------------------")
                break

            order = int(m.group(1))
            alloc_flags = int(m.group(2),16)
            alloc_gfp = int(m.group(3),16)
            addr = int(m.group(4),16)
            caps = m.group(5).split("\n")
            stack_trace = m.group(6)

            alloc_page_record = AllocPageRecord(order=order, alloc_flags=alloc_flags, alloc_gfp=alloc_gfp, addr=addr, caps=caps, stack_trace=stack_trace)
            alloc_page_record.do_record()

        elif "BACK_TRACE_KMALLOC_START" in s:
            r = re.compile("^BACK_TRACE_KMALLOC_START\n"
                           "size: (0x[0-9a-f]+), flags: (0x[0-9a-f]+), page_size: (0x[0-9a-f]+)\n"
                           "addr: (0x[0-9a-f]+)\n\n"
                           "Recorded capabilities: \n(.*?)"
                           "Dumping stack: \n(.*?)$", re.DOTALL)
            m = r.match(s)
            if not m:
                print("Error when parsing BACK_TRACE_KMALLOC_START", file=sys.stderr)
                if DEBUG:
                    print("-----------------------")
                    print(s)
                    print("-----------------------")
                break

            size = int(m.group(1),16)
            flags = int(m.group(2),16)
            page_size = int(m.group(3),16)
            addr = int(m.group(4),16)
            caps = m.group(5).split("\n")
            stack_trace = m.group(6)

            kmalloc_record = KmallocRecord(size=size, flags=flags, page_size=page_size, addr=addr, caps=caps, stack_trace=stack_trace)
            kmalloc_record.do_record()

        elif "BACK_TRACE_KFREE_START" in s:
            r = re.compile("^BACK_TRACE_KFREE_START\n"
                            "addr: (0x[0-9a-f]+)\n"
                            "(?:s: (.*?)|(free large kmalloc object))\n\n"
                            "Recorded capabilities: \n(.*?)"
                            "Dumping stack: \n(.*?)$", re.DOTALL)
            m = r.match(s)
            if not m:
                print("Error when parsing BACK_TRACE_KFREE_START", file=sys.stderr)
                if DEBUG:
                    print("-----------------------")
                    print(s)
                    print("-----------------------")
                break

            addr = int(m.group(1),16)
            if m.group(2):
                slub = m.group(2)
            elif m.group(3):
                slub = "LARGE OBJECT"
            else:
                print("Error when parsing BACK_TRACE_KFREE_START", file=sys.stderr)
                if DEBUG:
                    print("-----------------------")
                    print(s)
                    print("-----------------------")
                break
            caps = m.group(4).split("\n")
            stack_trace = m.group(5)

            kfree_record = KfreeRecord(addr=addr, slub=slub, caps=caps, stack_trace=stack_trace)
            kfree_record.do_record()

        elif "BACK_TRACE_KMEM_CACHE_ALLOC_START" in s:
            r = re.compile("^BACK_TRACE_KMEM_CACHE_ALLOC_START\n"
                           "s: (.*?), flags: (0x[0-9a-f]+), page_size: (0x[0-9a-f]+)\n"
                            "addr: (0x[0-9a-f]+)\n\n"
                            "Recorded capabilities: \n(.*?)"
                            "Dumping stack: \n(.*?)$", re.DOTALL)
            m = r.match(s)
            if not m:
                print("Error when parsing BACK_TRACE_KMEM_CACHE_ALLOC_START", file=sys.stderr)
                if DEBUG:
                    print("-----------------------")
                    print(s)
                    print("-----------------------")
                break

            slub = m.group(1)
            flags = int(m.group(2),16)
            page_size = int(m.group(3),16)
            addr = int(m.group(4),16)
            caps = m.group(5).split("\n")
            stack_trace = m.group(6)

            kmem_cache_alloc_record = KmemCacheAllocRecord(slub=slub, flags=flags, page_size=page_size, addr=addr, caps=caps, stack_trace=stack_trace)
            kmem_cache_alloc_record.do_record()

        elif "BACK_TRACE_KMEM_CACHE_FREE_START" in s:
            r = re.compile("^BACK_TRACE_KMEM_CACHE_FREE_START\n"
                           "addr: (0x[0-9a-f]+)\n"
                           "s: (.*?)\n\n"
                           "Recorded capabilities: \n(.*?)"
                           "Dumping stack: \n(.*?)$", re.DOTALL)
            m = r.match(s)
            if not m:
                print("Error when parsing BACK_TRACE_KMEM_CACHE_FREE_START", file=sys.stderr)
                if DEBUG:
                    print("-----------------------")
                    print(s)
                    print("-----------------------")
                break 
        
            addr = int(m.group(1),16)
            slub = m.group(2)
            caps = m.group(3).split("\n")
            stack_trace = m.group(4)

            kmem_cache_free_record = KmemCacheFreeRecord(addr=addr, slub=slub, caps=caps, stack_trace=stack_trace)
            kmem_cache_free_record.do_record()
           

def do_test():
    pass


def do_work(directory):
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            print(filepath)
            parse_data_file(filepath)
            print("Number of unique stack traces: ", len(stack_trace_hashes))
    
    print("done")
        
    
if __name__ == "__main__":
    do_work(sys.argv[1])


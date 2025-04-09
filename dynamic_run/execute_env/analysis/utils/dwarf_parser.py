import json
import os
import sys
from elftools.elf.elffile import ELFFile

if __name__ == '__main__':
    # 打开 ELF 文件
    with open(sys.argv[1], 'rb') as f:
    # with open('test/a.out', 'rb') as f:
        elffile = ELFFile(f)

        # 获取 DWARF 调试信息
        if elffile.has_dwarf_info():
            dwarfinfo = elffile.get_dwarf_info()
        else:
            print('no dwarf info')

        # 遍历每个编译单元
        result_list = []
        for cu in dwarfinfo.iter_CUs():
            # 获取行号程序
            lineprog = dwarfinfo.line_program_for_CU(cu)

            # 遍历每个行号条目
            for entry in lineprog.get_entries():
                # 如果条目包含地址和行号信息
                if entry.state is not None and entry.state.file is not None and entry.state.line is not None:
                    file_entry = lineprog['file_entry'][entry.state.file - 1]
                    dir_name = lineprog['directories'][file_entry.dir_index]['DW_LNCT_path'].decode('utf-8')
                    file_name = file_entry.name.decode('utf-8')
                    # print(lineprog.__dict__)
                    # print(entry.state.__dict__)
                    file_path = os.path.join(dir_name, file_name)
                    result = {
                        'Address': hex(entry.state.address),
                        'File': file_path,
                        'Line': entry.state.line
                    }
                    result_list.append(result)

        # 将结果保存到 JSON 文件中
        with open('result.json', 'w') as json_file:
            json.dump(result_list, json_file, indent=4)


"""
'directories':
[
    Container({'DW_LNCT_path': b'/root/pwn/linux-6.2.6'}), 
    Container({'DW_LNCT_path': b'init'}), 
    Container({'DW_LNCT_path': b'./arch/x86/include/asm'}), 
    Container({'DW_LNCT_path': b'./include/trace/events'}), 
    Container({'DW_LNCT_path': b'./include/linux'}), 
    Container({'DW_LNCT_path': b'./include/asm-generic/bitops'}), 
    Container({'DW_LNCT_path': b'./include/linux/sched'}),
    Container({'DW_LNCT_path': b'./include/linux/atomic'}), 
    Container({'DW_LNCT_path': b'./include/uapi/asm-generic'}), 
    Container({'DW_LNCT_path': b'./include/asm-generic'}), 
    Container({'DW_LNCT_path': b'./include/uapi/linux'}), 
    Container({'DW_LNCT_path': b'./arch/x86/include/asm/fpu'}), 
    Container({'DW_LNCT_path': b'./include/vdso'}), 
    Container({'DW_LNCT_path': b'./include/net'}), 
    Container({'DW_LNCT_path': b'./include/linux/device'}), 
    Container({'DW_LNCT_path': b'./include/net/netns'}), 
    Container({'DW_LNCT_path': b'./include/uapi/linux/netfilter'}), 
    Container({'DW_LNCT_path': b'./include/linux/netfilter'}), 
    Container({'DW_LNCT_path': b'./include/trace/stages'}), 
    Container({'DW_LNCT_path': b'./include/kunit'})
],
'file_names': 
[
    Container({'DW_LNCT_path': b'main.c', 'DW_LNCT_directory_index': 1}), 
    Container({'DW_LNCT_path': b'smp.h', 'DW_LNCT_directory_index': 2}),
    Container({'DW_LNCT_path': b'initcall.h', 'DW_LNCT_directory_index': 3}), 
    Container({'DW_LNCT_path': b'main.c', 'DW_LNCT_directory_index': 1}), 
    Container({'DW_LNCT_path': b'err.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'memblock.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'ktime.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'current.h', 'DW_LNCT_directory_index': 2}), 
    Container({'DW_LNCT_path': b'sched.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'stackprotector.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'random.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'trace_events.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'perf_event.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'list.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'efi.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'instrumented-non-atomic.h', 'DW_LNCT_directory_index': 5}), 
    Container({'DW_LNCT_path': b'instrumented.h', 'DW_LNCT_directory_index': 4}), 
    Container({'DW_LNCT_path': b'bitops.h', 'DW_LNCT_directory_index': 2})
"""
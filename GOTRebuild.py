import json
import os
import sys

file_path = "libaudioprocessing_asan_bss.s"
file_m_path = "libaudioprocessing_asan_bss_got.s"
jump_table_path = "JumpTable"

fr = open(file_path, 'r')
lines = fr.readlines()
fr.close()

fr = open(jump_table_path, 'r')
contents = fr.readlines()
fr.close()
jump_table_entries = json.loads(contents[0])
jump_table_sizes = json.loads(contents[1])
jump_table_offsets = json.loads(contents[3])
jump_table_br_addrs = json.loads(contents[4])



''' GOT Rebuild Start '''
got_func_list = []
got_section = False
for line in lines:
    if line.startswith('.section'):
        if '.record_got' in line:
            got_section = True
        else:
            got_section = False

    if got_section:
        if '.quad' in line:
            func_name = line.split('.quad ')[1]
            got_func_list.append(func_name.strip())
            
if len(got_func_list) == 0:
    print("not got should be change")
    fw = open(file_m_path, 'w')
    fw.writelines(lines)
    fw.close()
    sys.exit(0)
    
for got_func in got_func_list:
    for i in range(len(lines)):
        line = lines[i]

        if line.startswith('%s:' % got_func):
            lines[i] = '.p2align 3\n' + lines[i]

got_base_offset = {}
got_line = {}
for i in range(len(lines)):
    line = lines[i]

    if 'adrp' in line and '.got_start' in line:
        reg = line.split('adrp ')[1].split(',')[0]
        got_base_offset[reg] = []
        got_line[reg] = i

        next_line = lines[i + 1]
        if 'sub' in next_line:
            sub_offset = next_line.split((', %s, ' % reg))[1].strip()
            if '0x' in sub_offset:
                print("sub HEX value %s" % sub_offset)
            
            got_base_offset[reg].append('-')
            got_base_offset[reg].append(sub_offset)        
        elif 'add' in next_line:
            add_offset = next_line.split((', %s, ' % reg))[1].strip()
            if '0x' in sub_offset:
                print("add HEX value %s" % sub_offset)

            got_base_offset[reg].append('+')
            got_base_offset[reg].append(add_offset)      
        else:
            print("no sub or add next to adrp .got_start " + i)
    else:
        if len(got_line) > 0:
            if 'ldr ' in line and '.LC_ASAN_ENTER_' not in line:
                for reg in got_line:
                    if ('ldr %s, [%s, #' % (reg, reg)) in line:
                        ldr_offset = line.split('#')[1].split(']')[0]

                        sub_or_add = got_base_offset[reg][0]
                        sub_or_add_offset = got_base_offset[reg][1]
                        if sub_or_add == '-':
                            got_offset = int(ldr_offset, 16) - int(sub_or_add_offset)
                        elif sub_or_add == '+':
                            got_offset = int(ldr_offset, 16) + int(sub_or_add_offset)
                        else:
                            print("former no sub or add next to adrp .got_start " + i)
                        got_func = got_func_list[int(got_offset / 8)]

                        lines[got_line[reg]] = '\tadrp %s, :got:%s\n' % (reg, got_func)
                        lines[got_line[reg] + 1] = '\tsub %s, %s, 0\n' % (reg, reg)
                        lines[i] = '\tldr %s, [%s, :got_lo12:%s]\n' % (reg, reg, got_func)

                        got_base_offset.pop(reg)
                        got_line.pop(reg)

                        break
''' GOT Rebuild End '''


''' RODATA Rebuild Start '''
rodata_label_map = {}
rodata_section = False
rodata_start_addr = False
br_ins_map = {}
for i in range(len(lines)):
    line = lines[i]

    if line.startswith('.section'):
        if '.rodata' in line:
            rodata_section = True
        else:
            rodata_section = False

    if rodata_section:
        if line.startswith('.LC'):
            addr = line.split('LC')[1].split(':')[0]
            if int(addr, 16) in jump_table_entries:
                rodata_label_map[int(addr, 16)] = i

            if not rodata_start_addr:
                rodata_start_addr = addr
    
    if line.startswith('\tbr x'):
        if lines[i - 1].startswith('.LC'):
            addr = lines[i - 1].split('LC')[1].split(':')[0]
            if int(addr, 16) in jump_table_br_addrs:
                br_ins_map[int(addr, 16)] = i

rodata_base_offset = {}
rodata_line = {}
for i in range(len(lines)):
    line = lines[i]

    if 'adrp' in line and '.rodata_start' in line:
        reg = line.split('adrp ')[1].split(',')[0]
        rodata_base_offset[reg] = []
        rodata_line[reg] = i

        next_line = lines[i + 1]
        if 'sub' in next_line:
            sub_offset = next_line.split((', %s, ' % reg))[1].strip()
            if '0x' in sub_offset:
                print("sub HEX value %s" % sub_offset)
            
            rodata_base_offset[reg].append('-')
            rodata_base_offset[reg].append(sub_offset)        
        elif 'add' in next_line:
            add_offset = next_line.split((', %s, ' % reg))[1].strip()
            if '0x' in sub_offset:
                print("add HEX value %s" % sub_offset)

            rodata_base_offset[reg].append('+')
            rodata_base_offset[reg].append(add_offset)      
        else:
            print("no sub or add next to adrp .rodata_start " + i)
    else:
        if len(rodata_line) > 0:
            if 'add ' in line and '.LC_ASAN_ENTER_' not in line:
                for reg in rodata_line:
                    if ('add %s, %s, #' % (reg, reg)) in line:
                        add_offset = line.split('#')[1].strip()

                        sub_or_add = rodata_base_offset[reg][0]
                        sub_or_add_offset = rodata_base_offset[reg][1]
                        if sub_or_add == '-':
                            rodata_offset = int(add_offset, 16) - int(sub_or_add_offset)
                        elif sub_or_add == '+':
                            rodata_offset = int(add_offset, 16) + int(sub_or_add_offset)
                        else:
                            print("former no sub or add next to adrp .got_start " + i)
                        rodata_label = '.LC' + hex(int(rodata_start_addr, 16) + rodata_offset)[2:]

                        lines[rodata_line[reg]] = '\tadrp %s, %s\n' % (reg, rodata_label)
                        lines[rodata_line[reg] + 1] = '\tsub %s, %s, 0\n' % (reg, reg)
                        lines[i] = '\tadd %s, %s, :lo12:%s\n' % (reg, reg, rodata_label)

                        rodata_base_offset.pop(reg)
                        rodata_line.pop(reg)

                        break
            elif 'ldr ' in line and '.LC_ASAN_ENTER_' not in line:
                for reg in rodata_line:
                    if (', [%s, #' % reg) in line:
                        ldr_offset = line.split('#')[1].split(']')[0]
                        
                        sub_or_add = rodata_base_offset[reg][0]
                        sub_or_add_offset = rodata_base_offset[reg][1]
                        if sub_or_add == '-':
                            rodata_offset = int(ldr_offset, 16) - int(sub_or_add_offset)
                        elif sub_or_add == '+':
                            rodata_offset = int(ldr_offset, 16) + int(sub_or_add_offset)
                        else:
                            print("former no sub or add next to adrp .got_start " + i)
                        rodata_label = '.LC' + hex(int(rodata_start_addr, 16) + rodata_offset)[2:]

                        lines[rodata_line[reg]] = '\tadrp %s, %s\n' % (reg, rodata_label)
                        lines[rodata_line[reg] + 1] = '\tsub %s, %s, 0\n' % (reg, reg)
                        lines[i] = '\tldr %s, [%s, :lo12:%s]\n' % (lines[i].split('ldr ')[1].split(',')[0], reg, rodata_label)

                        for j in range(len(lines)):
                            if lines[j].startswith(rodata_label) and '.p2align' not in lines[j]:
                                if lines[i].startswith('\tldr q'):
                                    lines[j] = '\t.p2align 4\n' + lines[j]
                                else:
                                    lines[j] = '\t.p2align 3\n' + lines[j]
                                break
                                
                        rodata_base_offset.pop(reg)
                        rodata_line.pop(reg)

                        break

for i in range(len(jump_table_entries)):
    jump_table_entry = jump_table_entries[i]
    jump_table_size = jump_table_sizes[i]
    jump_table_offset = jump_table_offsets[i]
    jump_table_br_addr = jump_table_br_addrs[i]

    if jump_table_offset == 1:
        for i in range(jump_table_size):
            ln = rodata_label_map[jump_table_entry] + i * 2
            if lines[ln + 1].startswith('\t.byte (.LC'):
                lines[ln + 1] = '\t.hword %s' % (lines[ln + 1].split('byte ')[1])
        
        found = False
        ln = br_ins_map[jump_table_br_addr]
        for i in range(20):
            if lines[ln - i].startswith('\tldrb '):
                lines[ln - i] = '\tldrh %s' % (lines[ln - i].split('ldrb ')[1])
                found = True
                break
        if not found:
            print("jump br has no ldrb")
''' RODATA Rebuild End '''



fw = open(file_m_path, 'w')
fw.writelines(lines)
fw.close()

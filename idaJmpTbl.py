import sys
#sys.path.append('D:\IDA\python\3')
import idautils
import idaapi
import ida_ua
# import logging
import struct
import ida_nalt
import json

# logging.basicConfig(level = logging.DEBUG)

def processFunctionsAndBlocks():
    """
    process all the functions and their basic blocks that ida recognizes
    params:
        output: protobuf file path
    returns:
    """
    functions = set()
    jump_table_path = "JumpTable"
    #module = blocks_pb2.module()
    insts = set()
    # dummy function
    # pbFunc = module.fuc.add()
    # pbFunc.va = 0
    # iterate over all instructions
    cases_num = []
    loc_list = []
    element_size_list = []
    instr_addr_list = []
    successor_addr_list = []
    #test_disam = Dword(long 0x3A3EC)
    #print(test_disam)
    for head in idautils.Heads():
        if idc.is_code(idc.get_full_flags(head)):
            switch_info = ida_nalt.get_switch_info(head)  ### indirect jump地址
            #print("this is switch_info:", switch_info)
            if (switch_info and switch_info.jumps != 0):
                #print("this is switch_info: ", switch_info)
                loc = switch_info.jumps
                #print("this is loc: ", loc)
                loc_list.append(loc)
                element_num = switch_info.get_jtable_size()
                #print("this is element_num: ", element_num)
                cases_num.append(element_num)
                element_size = switch_info.get_jtable_element_size()
                #print("this is element_size: ", element_size)
                element_size_list.append(element_size)
                instruc_addr = head
                #print("this is instruc_addr: ", instruc_addr)
                instr_addr_list.append(instruc_addr)
                successor_list = set()
                for num in range(0, element_num):
                    table_entry = loc+num*element_size
                    #print("this is table entry: " , table_entry)
                    successor = idc.get_bytes(table_entry, element_size)
                    #print("this is successor: ", successor)
                    format_str = "<l"
                    if element_size == 8:
                        format_str = "<q"
                    elif element_size == 2:
                        format_str = "<h"
                    elif element_size == 1:
                        format_str = "<B"
                    successor_addr = struct.unpack(format_str, successor)[0]
                    #print("this is successor_addr:",successor_addr)
                    successor_addr_list.append(successor_addr)


                    if successor_addr <= 0:
                        # logging.debug("table entry is negative, add jump table base address!")
                        successor_addr += loc
                    #print("this is successor_addr_loc:", successor_addr)
                    if successor_addr in successor_list:
                        continue


                    # successors
                    successor_list.add(successor_addr)

    ## save the protobuf result
    #with open(output, 'wb') as pbOut:
    #    pbOut.write(module.SerializeToString())
    ### 输出到文件
    #print(loc_list)
    #print(cases_num)
    #print(element_size_list)
    #print(instr_addr_list)
    #print(successor_addr_list)
    with open(jump_table_path, "w") as fd:
        json.dump(loc_list, fd)
    fd.close()
    fo = open(jump_table_path, "a")
    fo.write('\n')
    fo.close()

    with open(jump_table_path, "a") as fd:
        json.dump(cases_num, fd)
    fd.close()
    fo = open(jump_table_path, "a")
    fo.write('\n')
    fo.close()

    with open(jump_table_path, "a") as fd:
        json.dump(successor_addr_list, fd)
    fd.close()
    fo = open(jump_table_path, "a")
    fo.write('\n')
    fo.close()

    with open(jump_table_path, "a") as fd:
        json.dump(element_size_list, fd)
    fd.close()
    fo = open(jump_table_path, "a")
    fo.write('\n')
    fo.close()
    with open(jump_table_path, "a") as fd:
        json.dump(instr_addr_list, fd)
    fd.close()
    #print("sdfsdfsdfsdfsd")

if __name__ == '__main__':
    idaapi.auto_wait()
    processFunctionsAndBlocks()
    idc.process_config_line("ABANDON_DATABASE=YES")
    print("sdgsd")

    #print(cases_num)
    #idc.qexit(0)

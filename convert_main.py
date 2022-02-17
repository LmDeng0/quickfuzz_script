#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 1、找出所有的bbs_start-0
# 2、bbs_start-0对应的寄存器
# 3、往下寻找该寄存器对应的立即数（紧跟着的那句不算）
# 4、改立即数在bss_20220212225059.txt对应的十进制数
# 5、修改(.bss_start - 0)为.LC立即数的十六进制数
# 6、修改(.bss_start - 0)紧挨着的那句，把数字改为0
# 7、修改第3步的那句代码，立即数后（即#号后面的数字）修改为:lo12:.LC6d368（txt里的十进制数改为对应的十六进制数）
# 8、找到与第3步代码中寄存器和立即数一样的代码进行修改，修改方式与第7步一样

# .section .got
# .got_start:
# 改为：
# .section .record_got
# .record_got_start:

import json
import copy
import re

class Converter:
    def __init__(self, func_file, source_file):
        self.func_file = func_file
        self.source_file = source_file
        self.bss_flags = [".bss_start - 0"]
        self.const_prefix = "#0x"
        self.func_dict = {}
        self.func_addr = []
        self.source_list = []
        self.format_list = []
        self.source_sections = [".section .got", ".got_start:"]
        self.convert_sections = [".section .record_got", ".record_got_start:"]
        self.cach_dict = {}
        self.cach_matcher = "adrp\s+(.*?),"
        self.value_matcher = "#0x([0-9a-z]{1,10000})"
        self.bss_rep_tmp = ".LC{0}"
        self.val_rep_temp = ":lo12:.LC{0}"
        self.init_func_dict()
        self.init_source_list()

    def init_func_dict(self):
        with open(self.func_file, "r") as f:
            self.func_dict = json.load(f)
            self.func_addr = [hex(int(v)) for v in self.func_dict.keys()]
        print(self.func_addr)

    def init_source_list(self):
        lines = []
        value_map = {}
        with open(self.source_file, "r") as f:
            lines = f.readlines()
        self.format_list = copy.deepcopy(lines)
        self.source_list = copy.deepcopy(lines)
        for i in range(len(lines)):
            l = lines[i]
            flag = True
            for f in self.bss_flags:
                if f.lower() not in l:
                    flag = False
                    break
            if flag is False:
                continue
            mh = re.search(self.cach_matcher, l, re.IGNORECASE)
            if mh is None:
                continue
            # 找到定义行，以及定义行的下一行。
            if mh.groups()[0] not in self.cach_dict:
                self.cach_dict[mh.groups()[0]] = []

            new_find_index = []
            self.cach_dict[mh.groups()[0]].append(new_find_index)
            new_find_index.append(i)
            if i+1 < len(lines) and mh.groups()[0] in lines[i + 1]:
                new_find_index.append(i + 1)
            if i + 1 >= len(lines):
                break

            sublines = lines[i + 1: len(lines)]
            # ldr w9, [x8, #0x334]
            # add x0, x0, #0x30c
            # 查找出现立即数的位置
            # 出现多次，保留第一次，且值相同的
            for j in range(len(sublines)):
                tmp_cach_matcher = "adrp\s+%s," % mh.groups()[0]
                tmp_cach = re.search(tmp_cach_matcher, sublines[j])
                # 遇到再次定义了
                if tmp_cach is not None:
                    break
                mt ="%s,\s+#0x([0-9a-z]{1,10000})" % mh.groups()[0]
                #print(mt)
                mtm = re.search(mt, sublines[j])
                if mtm is not None:
                    if i not in value_map:
                        value_map[i] = mtm.groups()[0]
                    if mtm.groups()[0].lower() == value_map[i].lower():
                        new_find_index.append(i+1+j)
                    # print(mtm.group())

    def gen_format_result(self):
        for cach, line_index_sets in self.cach_dict.items():
            for index_set in line_index_sets:
                if len(index_set) < 3:
                    continue
                l2 = self.format_list[index_set[2]]
                vm = re.search(self.value_matcher, l2)
                replace_value=None
                for v in self.func_addr:
                    if v.lower().endswith(vm.groups()[0].lower()):
                        replace_value = v[2: len(v)]
                rep_val = self.val_rep_temp.format(replace_value)
                rep_bss = self.bss_rep_tmp.format(replace_value)
                for i in range(len(index_set)):
                    if i == 0:
                        v_set = self.format_list[index_set[i]].split(",")
                        v_set[-1] = re.sub("\(.*?\)", rep_bss, v_set[-1])
                        self.format_list[index_set[i]] = ",".join(v_set)
                    elif i == 1:
                        # x0, x0, 592
                        v_set = self.format_list[index_set[i]].split(",")
                        v_set[-1] = re.sub("[0-9a-z]{1,1000}", "0", v_set[-1])
                        self.format_list[index_set[i]] = ",".join(v_set)
                    else:
                        self.format_list[index_set[i]] = re.sub(self.value_matcher, rep_val, self.format_list[index_set[i]])

    def section_rebuild(self):
        for i in range(len(self.format_list)):
            # 连续两行
            if i + 1 >= len(self.format_list):
                break
            l1 = self.format_list[i]
            l2 = self.format_list[i + 1]
            if self.source_sections[0] in l1 and self.source_sections[1] in l2:
                self.format_list[i] = l1.replace(self.source_sections[0], self.convert_sections[0])
                self.format_list[i+1] = l2.replace(self.source_sections[1], self.convert_sections[1])

    def dump_result(self, save_path):
        with open(save_path, 'w') as f:
            f.writelines(self.format_list)


if __name__ == "__main__":
    cvr = Converter("bbs_func.txt", "libaudioprocessing_asan.s")
    cvr.gen_format_result()
    cvr.section_rebuild()
    cvr.dump_result("libaudioprocessing_asan_bss.s")

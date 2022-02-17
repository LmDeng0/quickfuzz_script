#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 将
# tbnz w16, #0, .LC223ac
# 改为：
# tst w16, #1
# bne .LC223ac
# 寄存器不变，#0改为#1，
import re
import copy


class TbnzHanler:

    def __init__(self, err_file, source_file):
        self.err_file = err_file
        self.source_file = source_file
        self.save_path = "libaudioprocessing_asan_bss_got_tbnz.s"
        self.tbnz_matcher = "(tbnz.*)$"
        self.bne = "bne"
        self.tst = "tst"
        self.tbnz_list = []
        self.source_list = []
        self.format_list = []
        self.source_init()

    def source_init(self):
        err_info = []
        with open(self.err_file, 'r') as f:
            err_info = f.readlines()

        for l in err_info:
            m = re.search(self.tbnz_matcher, l)
            if m is not None and m.groups()[0] not in self.tbnz_list:
                self.tbnz_list.append(m.groups()[0])

        with open(self.source_file, 'r') as f:
            self.source_list = f.readlines()

    def info_format(self):
        for s in self.source_list:
            if len([tbnz for tbnz in self.tbnz_list if tbnz in s]) == 0:
                self.format_list.append(s)
            else:
                # tbnz w16, #0, .LC223ac
                # 改为：
                # tst w16, #1
                # bne .LC223ac
                s1 = copy.deepcopy(s)
                s2 = copy.deepcopy(s)
                s1 = s1.replace("tbnz", self.tst)
                s1 = s1.replace("#0", "#1")
                parts = s1.split(",")
                s1 = ",".join(parts[0:2])
                s1 += parts[2][-1]

                s2 = re.sub("tbnz.*,", self.bne, s2)
                print(s)
                print(s1)
                print(s2)
                self.format_list.append(s1)
                self.format_list.append(s2)
        with open(self.save_path, 'w') as f:
            f.writelines(self.format_list)



if __name__ == "__main__":
    th = TbnzHanler("error.txt", "libaudioprocessing_asan_bss_got.s")
    th.info_format()

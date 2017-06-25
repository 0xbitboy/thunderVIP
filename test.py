# -*- coding: utf-8 -*-
import check
import unittest

# 测试类
class CalTest(unittest.TestCase):
    def test(self):
        r = check.login("username", "password")
        print(r)

if __name__=='__main__':unittest.main()

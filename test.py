# -*- coding: utf-8 -*-
import login
import unittest

# 测试类
class CalTest(unittest.TestCase):
    def test(self):
        r = login.login("username", "password")
        print(r)

if __name__=='__main__':unittest.main()

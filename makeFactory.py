'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-09 14:32:40
LastEditors: YanQiaoYu
LastEditTime: 2020-10-12 11:39:06
FilePath: \Automated_MySQLAudit_Test\makeFactory.py
'''


'''
description: 存放一些通用的功能函数，提高复用能力
'''


import threading
from scapy.all import *

GloConfig = {
    "LocalIP":"10.32.128.38",
    "MySQLIP":"103.45.103.253",
    "MySQL_User":"",
    "MySQL_Password":"",
    "TimeOut":1    
}

class mySniff(threading.Thread):
    def __init__(self, timeout, filter, FuncName):
        threading.Thread.__init__(self)
        self.timeout = timeout
        self.filter = filter
        self.FuncName = FuncName

        self.packageStack= []

    def run(self):
        package = sniff(timeout=self.timeout, filter=self.filter)
        if package:
            print("[{}]Capture Successfully!:{}".format(self.FuncName, package))
        self.packageStack.append(package)


    def saveResult(self, FileName,FuncName):
        wrpcap(FileName, self.packageStack.pop())
        print("[{}]Capture Save!".format(FuncName))

def SniffDeco(timeout, filterString, FileDir):
    def deco(func):
        def wrapper(*args, **kw):
            #获取函数名
            FuncName = func.__qualname__.split('.')[1]

            #1.开启抓包
            thread = mySniff(timeout, filterString, FuncName)
            thread.start()

            print('[{}]Make Begin'.format(FuncName))
            dicResult = func(*args, **kw)
            print('[{}]Make Finish'.format(FuncName))  

            thread.join()
            #3.保存抓包结果
            thread.saveResult(FileDir+FuncName+".pcap", FuncName) 

            return dicResult
        return wrapper
    return deco

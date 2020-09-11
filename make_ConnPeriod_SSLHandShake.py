'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-11 11:40:34
LastEditors: YanQiaoYu
LastEditTime: 2020-09-11 14:22:25
FilePath: \Automated_MySQLAudit_Test\make_ConnPeriod_SSLHandShake.py
'''
import mysql.connector
import sys
import os
from makeFactory import mySniff, GloConfig

class make_SSL_HandShake:
    def __init__(self):
        #测试脚本部署所在机器的IP地址
        self.LocalIP = GloConfig["LocalIP"]
        #测试数据库所在的IP地址
        self.MySQLIP = GloConfig["MySQLIP"]
        self.MySQL_User = GloConfig["MySQL_User"]
        self.MySQL_Password = GloConfig["MySQL_Password"]
        #抓包时常，如果交互时间比较长，可以适当调整
        self.timeout = GloConfig["TimeOut"]

        '''
        如下区域定义属于自己填写的变量
        '''        
        #过滤条件，这个无需修改
        self.filterString = "host {} and host {}".format(self.LocalIP, self.MySQLIP)
        #抓好的包的存放位置
        self.FileDir = "./Packet/02-ConnPeriod/03-SSLHandShake/"
        #新建目录
        if os.path.exists(self.FileDir) and os.path.isdir(self.FileDir):
            pass
        else:
            os.makedirs(self.FileDir)  

    def make_SSLHandShake(self):
        FuncName = sys._getframe().f_code.co_name

        #开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='Flase',
                            )

        #保存抓包结果
        thread.join()
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName) 

        cnx.close()         

make_SSL_HandShake = make_SSL_HandShake()
make_SSL_HandShake.make_SSLHandShake()
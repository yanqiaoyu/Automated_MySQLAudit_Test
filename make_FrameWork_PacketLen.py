'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-09 15:50:43
LastEditors: YanQiaoYu
LastEditTime: 2020-09-10 15:41:31
FilePath: \Automated_MySQLAudit_Test\make_FrameWork_PacketLen.py
'''
import mysql.connector
import sys
import os
from makeFactory import mySniff, GloConfig

class make_FrameWork_PacketLen:
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
        self.FileDir = "./Packet/01-FrameWork/02-PacketLength/"
        #新建目录
        if os.path.exists(self.FileDir) and os.path.isdir(self.FileDir):
            pass
        else:
            os.makedirs(self.FileDir)    

    #不分片场景报文
    def make_DoNotFragm(self):

        FuncName = sys._getframe().f_code.co_name
        
        #1.开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #2.发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            )
        cmd = cnx.cursor()
        cmd.execute("show databases;")                             

        thread.join()
        #3.保存抓包结果
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)

        cmd.close()
        cnx.close()

    #分片场景报文
    def make_Fragm(self):

        FuncName = sys._getframe().f_code.co_name

        #发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            )
        

        #开启抓包
        thread = mySniff(30, self.filterString, FuncName)
        thread.start()


        cmd = cnx.cursor()     
        cmd.execute(
            "Create Database If Not Exists MySQL_Audit_Test Character Set UTF8;"
        )
        cmd.execute(
            "set global max_allowed_packet=524288000;"
        )
        cmd.execute(
            "use MySQL_Audit_Test;"
        )
        cmd.execute(
            "drop table student;"
        )        
        #建表
        cmd.execute("create table if not exists student( \
                    id int(4) primary key not null auto_increment, \
                    phone longtext not null \
                    );")          

        #插入数据
        cmd.execute(
            "INSERT INTO student (phone) VALUES ('{}')".format("1"*(2**24-41))
        )                   

        cnx.commit()
        
        #保存抓包结果
        thread.join()
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)

        cmd.close()
        cnx.close()


make_FrameWork_PacketLen = make_FrameWork_PacketLen()
make_FrameWork_PacketLen.make_Fragm()
make_FrameWork_PacketLen.make_DoNotFragm()
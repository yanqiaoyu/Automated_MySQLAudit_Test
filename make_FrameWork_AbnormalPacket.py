'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-10 14:48:29
LastEditors: YanQiaoYu
LastEditTime: 2020-09-10 17:39:59
FilePath: \Automated_MySQLAudit_Test\make_FrameWork_AbnormalPacket.py
'''
import mysql.connector
import sys
import os
from makeFactory import mySniff, GloConfig
import requests
from scapy.all import *

class make_FrameWork_AbnormalPacket:

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
        self.FileDir = "./Packet/01-FrameWork/04-AbnormalPacket/"
        #新建目录
        if os.path.exists(self.FileDir) and os.path.isdir(self.FileDir):
            pass
        else:
            os.makedirs(self.FileDir)  
            
    # 不经过3306端口的MySQL协议报文
    def make_Not3306Port(self):
        FuncName = sys._getframe().f_code.co_name
        
        #1.开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        try:
            #2.发送登陆报文
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                port = 3307,
                                connection_timeout = 3,
                                )                   
        except:
            print("Enter Except")
        
        finally:
            thread.join()
            #3.保存抓包结果
            thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)  

            #cnx.close()      
            
    #经过3306端口的非MySQL协议报文
    def make_3306NotMySQLPacket(self):
        #使用request构造请求
        url = "http://" + GloConfig["MySQLIP"] + ":3306"
        payload = { 
            'province': '四川'
        }        
        r = requests.get(url, params=payload)

    #有请求，无响应
    def make_OnlyRequest(self):
        FuncName = sys._getframe().f_code.co_name
        
        #1.开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #2.发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            )
                           
        thread.join()
        #3.保存抓包结果
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)

        cnx.close()

        #读取
        packet = rdpcap(self.FileDir + FuncName + ".pcap")
        #过滤IP为只有请求，没有响应
        TargetPacket = packet.filter(lambda s: s.sprintf("%IP.src%") == GloConfig["LocalIP"])
        wrpcap(self.FileDir + FuncName + ".pcap", TargetPacket)

    #有响应，无请求
    def make_OnlyResponse(self):
        FuncName = sys._getframe().f_code.co_name
        
        #1.开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #2.发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            )
                           
        thread.join()
        #3.保存抓包结果
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)

        cnx.close()

        #读取
        packet = rdpcap(self.FileDir + FuncName + ".pcap")
        #过滤IP为只有请求，没有响应
        TargetPacket = packet.filter(lambda s: s.sprintf("%IP.src%") == GloConfig["MySQLIP"])
        wrpcap(self.FileDir + FuncName + ".pcap", TargetPacket)

make_FrameWork_AbnormalPacket = make_FrameWork_AbnormalPacket()
make_FrameWork_AbnormalPacket.make_Not3306Port()
make_FrameWork_AbnormalPacket.make_3306NotMySQLPacket()
make_FrameWork_AbnormalPacket.make_OnlyRequest()
make_FrameWork_AbnormalPacket.make_OnlyResponse()
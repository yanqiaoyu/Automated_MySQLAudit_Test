'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-10 14:48:29
LastEditors: YanQiaoYu
LastEditTime: 2020-10-09 10:24:16
FilePath: \Automated_MySQLAudit_Test\make_FrameWork_SerialNum.py
'''
import mysql.connector
import sys
import os
from makeFactory import mySniff, GloConfig, SniffDeco

class make_FrameWork_SerialNum:
    #抓包时常，如果交互时间比较长，可以适当调整
    timeout = GloConfig["TimeOut"]
    #测试脚本部署所在机器的IP地址
    LocalIP = GloConfig["LocalIP"]
    #测试数据库所在的IP地址
    MySQLIP = GloConfig["MySQLIP"]
    '''
    如下区域定义属于自己填写的变量
    '''        
    #过滤条件，这个无需修改
    filterString = "host {} and host {}".format(LocalIP, MySQLIP)
    #抓好的包的存放位置
    FileDir = "./Packet/01-FrameWork/03-SerialNum/"    
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
        self.FileDir = "./Packet/01-FrameWork/03-SerialNum/"
        #新建目录
        if os.path.exists(self.FileDir) and os.path.isdir(self.FileDir):
            pass
        else:
            os.makedirs(self.FileDir)  
            
    #命令起始阶段，序列号从0开始，互过程中，序列号按+1的步长递增
    #构造登录场景即可观察到序列号的增长
    def make_SerialNumAdd(self):
        FuncName = sys._getframe().f_code.co_name

        #开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            )

        #保存抓包结果
        thread.join()
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName) 

        cnx.close()   

    #旧命令结束后，新命令开始，序列号归0   
    def make_SerialNumReset(self):
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

        cnx.close()       
        

    '''
	#命令起始阶段，序列号从0开始，互过程中，序列号按+1的步长递增
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_03_001(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                database='DataSercurity'
                                )        
            cmd = cnx.cursor()
            cmd.execute("desc Test1")
            cmd.fetchall()
        except:
            cmd.close()
            cnx.close()

    '''
	#不同的命令，序列号重新计时，互过程中，序列号按+1的步长递增
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_03_002(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                database='DataSercurity'
                                )        
            cmd = cnx.cursor()
            cmd.execute("desc Test1")
            cmd.fetchall()
            cmd.execute("desc Test2")
            cmd.fetchall()
        except:
            cmd.close()
            cnx.close()

make_FrameWork_SerialNum = make_FrameWork_SerialNum()

#make_FrameWork_SerialNum.Datasec_audit_mysql_protocol_03_001()
#make_FrameWork_SerialNum.Datasec_audit_mysql_protocol_03_002()
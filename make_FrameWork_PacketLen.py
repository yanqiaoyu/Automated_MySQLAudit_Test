'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-09 15:50:43
LastEditors: YanQiaoYu
LastEditTime: 2020-11-26 10:22:29
FilePath: \Automated_MySQLAudit_Test\make_FrameWork_PacketLen.py
'''
import mysql.connector
import sys
import os
from makeFactory import GloConfig, SniffDeco

class make_FrameWork_PacketLen:
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
    FileDir = "./Packet/01-FrameWork/02-PacketLength/"
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

    '''
	#不分包场景
	#绝大多数场景都是不分包场景，无需特别测试，select一组较大的数据，但是不超过分包阈值
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_02_001(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                database='DataSercurity'
                                )        
            cmd = cnx.cursor()
            cmd.execute("select PhoneNum from Test1 where id <= 100;")
            cmd.fetchall()
        except:
            cmd.close()
            cnx.close()

    '''
	#分包场景
    '''
    @SniffDeco(30, filterString, FileDir)
    def Datasec_audit_mysql_protocol_02_002(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
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
                "INSERT INTO student (phone) VALUES ('{}')".format("1"*(2**24-1))
            )                   

            cnx.commit()
        except:
            cmd.close()
            cnx.close()

    '''
	#1K场景
    '''
    @SniffDeco(5, filterString, FileDir)
    def Datasec_audit_mysql_protocol_1K(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
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
                "INSERT INTO student (phone) VALUES ('{}2')".format("1"*(2**10-41))
            )                   

            cnx.commit()
        except:
            cmd.close()
            cnx.close()


    '''
	#略大于1K场景
    '''
    @SniffDeco(5, filterString, FileDir)
    def Datasec_audit_mysql_protocol_greater_than_1K(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
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
                "INSERT INTO student (phone) VALUES ('{}2')".format("1"*(2**10-40))
            )                   

            cnx.commit()
        except:
            cmd.close()
            cnx.close()


make_FrameWork_PacketLen = make_FrameWork_PacketLen()

#make_FrameWork_PacketLen.Datasec_audit_mysql_protocol_02_001()
#make_FrameWork_PacketLen.Datasec_audit_mysql_protocol_02_002()
#make_FrameWork_PacketLen.Datasec_audit_mysql_protocol_1K()
make_FrameWork_PacketLen.Datasec_audit_mysql_protocol_greater_than_1K()
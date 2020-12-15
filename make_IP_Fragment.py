'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-09 10:01:15
LastEditors: YanQiaoYu
LastEditTime: 2020-11-11 11:13:53
FilePath: \Automated_MySQLAudit_Test\make_IP_Fragment.py
'''
import mysql.connector
import sys
import os
from makeFactory import GloConfig, SniffDeco

class make_FrameWork_Basic:
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
    FileDir = "./Packet/IP_Fag/"    
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
        self.FileDir = "./Packet/IP_Fag/"  
        #新建目录
        if os.path.exists(self.FileDir) and os.path.isdir(self.FileDir):
            pass
        else:
            os.makedirs(self.FileDir)

    '''
    定长整数（Fixed-Length Integer Types）
    发送一个SQL指令，切换到一个不存在的数据库use NoneExist;
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_01_001(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("use NoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExistNoneExist;")
        except:
            cmd.close()
            cnx.close()





make_FrameWork_Basic = make_FrameWork_Basic()

make_FrameWork_Basic.Datasec_audit_mysql_protocol_01_001()

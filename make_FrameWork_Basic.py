'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-09 10:01:15
LastEditors: YanQiaoYu
LastEditTime: 2020-10-08 16:00:08
FilePath: \Automated_MySQLAudit_Test\make_FrameWork_Basic.py
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
    FileDir = "./Packet/01-FrameWork/01-Basic/"    
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
        self.FileDir = "./Packet/01-FrameWork/01-Basic/"
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
            cmd.execute("use NoneExist;")
        except:
            cmd.close()
            cnx.close()

    '''
    长度编码整数类型（Length-Encoded Integer Type）
    构造一个含有长度编码整数类型的包
    事实上，绝大多数的包的长度都是这种整数类型，例如，发送一条SQL指令 `show databases;`
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_01_002(self):
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            )

        cmd = cnx.cursor()
        cmd.execute("show databases;")
        cmd.fetchall()
        
        cmd.close()
        cnx.close()


    '''
    定长字符串（FixedLengthString）
    发送一个不完整的SQL指令，例如"select * from X;"
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_01_003(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                database='DataSercurity'
                                )        
            cmd = cnx.cursor()
            cmd.execute("select * from X;")
        except:
            cmd.close()
            cnx.close()

    '''
    00结尾字符串（NullTerminatedString）
    一个initial handshake包就含有这种类型的包（string(NUL)），即服务器版本信息。进行一次正常的登陆操作即可
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_01_004(self):
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            )
        cnx.close()

    '''
    变长字符串（LengthEncodedString）
    事实上一个initial handshake包就含有这种类型的包（string(lenenc)）,即auth-plugin-data-part-2字段。进行一次正常的登陆操作即可
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_01_005(self):
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            )
        cnx.close()


    '''
    长度由其他部分确认字符串（VariableLengthString）
    例如，"select * from XX where XX = XX"
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_01_006(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                database='DataSercurity'
                                )        
            cmd = cnx.cursor()
            cmd.execute("select Addr from Test1 where id =2;")
        except:
            cmd.close()
            cnx.close()

    '''
    EOF结尾的字符串（RestOfPacketString）
    发送一个SQL指令，删除一个不存在的数据库`drop database ABCD;`
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_01_007(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("drop database ABCD;")
        except:
            cmd.close()
            cnx.close()

    '''
    非法字符串类型
    构造一个含有非法字符串的包，例如在SQL查询语句中添加中文
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_01_008(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                database='DataSercurity'
                                )        
            cmd = cnx.cursor()
            cmd.execute("sel中文ect * from Test1 where id =测试;")
        except:
            cmd.close()
            cnx.close()




make_FrameWork_Basic = make_FrameWork_Basic()

#make_FrameWork_Basic.Datasec_audit_mysql_protocol_01_001()
#make_FrameWork_Basic.Datasec_audit_mysql_protocol_01_002()
#make_FrameWork_Basic.Datasec_audit_mysql_protocol_01_003()
#make_FrameWork_Basic.Datasec_audit_mysql_protocol_01_004()
#make_FrameWork_Basic.Datasec_audit_mysql_protocol_01_005()
#make_FrameWork_Basic.Datasec_audit_mysql_protocol_01_006()
#make_FrameWork_Basic.Datasec_audit_mysql_protocol_01_007()
#make_FrameWork_Basic.Datasec_audit_mysql_protocol_01_008()
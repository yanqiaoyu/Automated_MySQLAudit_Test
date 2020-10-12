import mysql.connector
import sys
import os
from makeFactory import GloConfig, SniffDeco

class make_FrameWork_Log:
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
    FileDir = "./Packet/01-FrameWork/05-Log/"    
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
        self.FileDir = "./Packet/01-FrameWork/05-Log/"
        #新建目录
        if os.path.exists(self.FileDir) and os.path.isdir(self.FileDir):
            pass
        else:
            os.makedirs(self.FileDir)

    '''
    arg字段(执行命令的参数)
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_05_001(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("show databases;")
            cmd.fetchall()
            cmd.execute("desc DataSercurity.Test1;")
            cmd.fetchall()
        except:
            cmd.close()
            cnx.close()

    '''
    arg字段(执行命令的参数)
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_05_002(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("use DataSercurity;")
        except:
            cmd.close()
            cnx.close()

    '''
    response字段（命令返回结果）
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_05_003(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("use DataSercurity;")
            cmd.execute("select PhoneNum from Test1 limit 1, 50;")
            cmd.fetchall()
        except:
            cmd.close()
            cnx.close()

    '''
    rows字段（命令影响的行数）
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_05_004(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                database='DataSercurity'
                                )        
            cmd = cnx.cursor()

            cmd.execute("Create Table If Not Exists `Test99`(   \
                                `ID` Bigint(16) unsigned Primary key Auto_Increment, \
                                `PhoneNum` varchar(22), \
                                `MailAddr` text, \
                                `SSN` varchar(22) \
                                )Engine InnoDB;")

            cmd.execute("insert into Test99 (ID, PhoneNum, MailAddr, SSN) values (1, 1,2,3)")
            cmd.execute("insert into Test99 (ID, PhoneNum, MailAddr, SSN) values (2, 4,5,6)")
            cmd.execute("insert into Test99 (ID, PhoneNum, MailAddr, SSN) values (3, 7,8,9)")

            cmd.execute("update Test99 set PhoneNum = 110 where id != 3;")    

            cmd.execute("delete from Test99 where id = 3;") 

            cmd.execute("drop table Test99;")
        except:
            pass
        finally:
            cnx.commit()
            cmd.close()
            cnx.close()

    '''
    src_ip&&dst_ip
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_05_005(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("use DataSercurity;")
        except:
            cmd.close()
            cnx.close()

    '''
    src_port&&dst_port
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_05_006(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("use DataSercurity;")
        except:
            cmd.close()
            cnx.close()

    '''
    user
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_05_007(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("use DataSercurity;")

            cmd.close()
            cnx.close()

            cnx = mysql.connector.connect(user="test", password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("show databases;")
        except:
            pass
        finally:
            cmd.close()
            cnx.close()

    '''
    success
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_05_008(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("use DataSercurity;")
            cmd.execute("use ABCD;")

        except:
            pass
        finally:
            cmd.close()
            cnx.close()

    '''
    ts
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_05_009(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cmd.execute("use DataSercurity;")

        except:
            pass
        finally:
            cmd.close()
            cnx.close()


make_FrameWork_Log = make_FrameWork_Log()
#make_FrameWork_Log.Datasec_audit_mysql_protocol_05_001()
#make_FrameWork_Log.Datasec_audit_mysql_protocol_05_002()
#make_FrameWork_Log.Datasec_audit_mysql_protocol_05_003()
#make_FrameWork_Log.Datasec_audit_mysql_protocol_05_004()
#make_FrameWork_Log.Datasec_audit_mysql_protocol_05_005()
#make_FrameWork_Log.Datasec_audit_mysql_protocol_05_006()
#make_FrameWork_Log.Datasec_audit_mysql_protocol_05_007()
#make_FrameWork_Log.Datasec_audit_mysql_protocol_05_008()
#make_FrameWork_Log.Datasec_audit_mysql_protocol_05_009()
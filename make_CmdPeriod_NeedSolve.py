'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-11 11:44:43
LastEditors: YanQiaoYu
LastEditTime: 2020-10-10 18:41:58
FilePath: \Automated_MySQLAudit_Test\make_CmdPeriod_NeedSolve.py
'''
import mysql.connector
import sys
import os
from makeFactory import mySniff, GloConfig, SniffDeco

class make_NeedSolveCmd:

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
    FileDir = "./Packet/02-ConnPeriod/03-NeedSolveCmd/"       

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
        self.FileDir = "./Packet/02-ConnPeriod/03-NeedSolveCmd/"
        #新建目录
        if os.path.exists(self.FileDir) and os.path.isdir(self.FileDir):
            pass
        else:
            os.makedirs(self.FileDir)     

    '''
    0x02 COM_INIT_DB:use
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_10_001(self):
        try:
            cnx = mysql.connector. connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cnx.cmd_init_db("MySQL_Audit_Test")
            cnx.cmd_init_db("NoneExistDataBases")

        except:
            pass
        finally:
            cmd.close()
            cnx.close()

    '''
    0x03 COM_QUERY:select
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_10_002(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            statement = "\
                use MySQL_Audit_Test;\
                select * from student where id = 1000;\
                select * from None;\
                "
            for result in cnx.cmd_query_iter(statement):
                if 'columns' in result:
                    columns = result['columns']
                    rows = cnx.get_rows()

        except:
            pass
        finally:
            cnx.close()

    '''
    0x03 COM_QUERY:create
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_10_003(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )  
            cmd = cnx.cursor()
              
            cmd.execute("Create Database If Not Exists TmpDataBases;")  
            cmd.execute("use TmpDataBases;")
            cmd.execute("Create Table If Not Exists `TestTmp`(   \
                `ID` Bigint(16) unsigned Primary key Auto_Increment, \
                `SSN` varchar(22) \
                )Engine InnoDB;")

            cmd.execute("drop table TestTmp;")
            cmd.execute("drop DATABASE TmpDataBases;")
            cmd.execute("drop DATABASE ABCD;")

        except:
            pass
        finally:
            cnx.close()

    '''
    0x03 COM_QUERY:update
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_10_004(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )  
            cmd = cnx.cursor()
              
            cmd.execute("Create Database If Not Exists TmpDataBases;")  
            cmd.execute("use TmpDataBases;")
            cmd.execute("Create Table If Not Exists `TestTmp`(   \
                `ID` Bigint(16) unsigned Primary key Auto_Increment, \
                `SSN` varchar(22) \
                )Engine InnoDB;")

            cmd.execute("insert into TestTmp (ID, SSN) values (1, 1234567890)")
            cmd.execute("update TestTmp set SSN = 110 where id = 1;")
            cmd.execute("update TestTmp set SSN = 110 where id = 2;")

            cmd.execute("drop table TestTmp;")
            cmd.execute("drop DATABASE TmpDataBases;")

        except:
            pass
        finally:
            cnx.close()


    '''
    0x03 COM_QUERY:drop
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_10_005(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )  
            cmd = cnx.cursor()
              
            cmd.execute("Create Database If Not Exists TmpDataBases;")  
            cmd.execute("use TmpDataBases;")
            cmd.execute("drop DATABASE TmpDataBases;")
            cmd.execute("drop DATABASE ABC;")

        except:
            pass
        finally:
            cnx.close()

    '''
    0x03 COM_QUERY:delete
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_10_006(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )  
            cmd = cnx.cursor()
              
            cmd.execute("Create Database If Not Exists TmpDataBases;")  
            cmd.execute("use TmpDataBases;")
            cmd.execute("Create Table If Not Exists `TestTmp`(   \
                `ID` Bigint(16) unsigned Primary key Auto_Increment, \
                `SSN` varchar(22) \
                )Engine InnoDB;")

            cmd.execute("insert into TestTmp (ID, SSN) values (1, 1234567890)")
            cmd.execute("delete from TestTmp where ID = 1")


            cmd.execute("drop table TestTmp;")
            cmd.execute("drop DATABASE TmpDataBases;")

        except:
            pass
        finally:
            cmd.close()
            cnx.close()

    '''
    0x03 COM_QUERY:show
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_10_007(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )  
            cmd = cnx.cursor()
            cmd.execute("show processlist;")
            cmd.fetchall()
            cmd.execute("show binary logs;")  
            cmd.fetchall()

        except:
            pass
        finally:
            cmd.close()
            cnx.close()

    '''
    0x03 COM_QUERY:flush
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_10_008(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )  
            cmd = cnx.cursor()
            cmd.execute("flush logs;")
            cmd.fetchall()
        except:
            pass
        finally:
            cmd.close()
            cnx.close()

    '''
    0x03 COM_QUERY:shutdown
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_10_009(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )  
            cmd = cnx.cursor()
            cmd.execute("shutdown;")

        except:
            pass
        finally:
            cmd.close()
            cnx.close()

    '''
    0x03 COM_QUERY:kill
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_10_010(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )  
            #cnx.cmd_process_kill(12)
            cnx.cmd_query('KILL 17')
        except:
            pass
        finally:
            cnx.close()


make_NeedSolveCmd = make_NeedSolveCmd()

#make_NeedSolveCmd.Datasec_audit_mysql_protocol_10_001()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_10_002()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_10_003()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_10_004()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_10_005()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_10_006()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_10_007()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_10_008()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_10_009()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_10_010()
'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-10-10 18:42:26
LastEditors: YanQiaoYu
LastEditTime: 2020-10-12 11:21:56
FilePath: \Automated_MySQLAudit_Test\make_CmdPeriod_NotNeedSolve.py
'''
import mysql.connector
from mysql.connector.constants import ClientFlag
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
    FileDir = "./Packet/02-ConnPeriod/04-NoNeedSolveCmd/"     

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
        self.FileDir = "./Packet/02-ConnPeriod/04-NoNeedSolveCmd/" 
        #新建目录
        if os.path.exists(self.FileDir) and os.path.isdir(self.FileDir):
            pass
        else:
            os.makedirs(self.FileDir)     

    '''
    0x11 COM_CHANGE_USER
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_11_002(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()

            cnx.cmd_change_user(username='123', password='456', database='mysql', charset=33)

        except:
            pass
        finally:
            cmd.close()
            cnx.close()


    '''
    0x1f COM_RESET_CONNECTION
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_11_007(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()

            cnx.cmd_reset_connection()

        except:
            pass
        finally:
            cmd.close()
            cnx.close()

    '''
    0x1b COM_SET_OPTION
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_11_006(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cnx.set_client_flags([ClientFlag.FOUND_ROWS, -ClientFlag.LONG_FLAG])
            cnx.reconnect()

        except:
            pass
        finally:
            cnx.close()

    '''
    0x0d COM_DEBUG
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_11_011(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cnx.cmd_debug()

        except:
            pass
        finally:
            cnx.close()

    '''
    0x16 COM_STMT_PREPARE
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_11_003(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cnx.cmd_stmt_prepare(b"show databases;")
            #cnx.cmd_stmt_execute()

        except Exception as e:
            print(e)
            
        finally:
            cnx.close()

    '''
    0x17 COM_STMT_EXECUTE
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_11_004(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cnx.cmd_stmt_prepare(b"show databases;")
            cnx.cmd_stmt_execute(1)

        except Exception as e:
            print(e)
            
        finally:
            cnx.close()

    '''
    0x19 COM_STMT_CLOSE
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_11_005(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cnx.cmd_stmt_prepare(b"show databases;")
            cnx.cmd_stmt_execute(1)
            cnx.cmd_stmt_close(1)

        except Exception as e:
            print(e)
            
        finally:
            cnx.close()

    '''
    0x1c COM_STMT_FETCH
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_11_008(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cnx.cmd_stmt_prepare(b"show databases;")
            cnx.cmd_stmt_execute(1)
            cnx.cmd_stmt_fetch(1)

        except Exception as e:
            print(e)
            
        finally:
            cnx.close()

    '''
    0x09 COM_STATISTICS
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_11_009(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )        
            cmd = cnx.cursor()
            cnx.cmd_statistics()

        except Exception as e:
            print(e)
            
        finally:
            cnx.close()

    '''
    COM_STMT_RESET = 0x1a
    '''
    @SniffDeco(timeout, filterString, FileDir)
    def Datasec_audit_mysql_protocol_11_010(self):
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )     
                                 
            cnx.cmd_stmt_prepare(b"show databases;")
            cnx.cmd_stmt_execute(1)
            cnx.cmd_stmt_reset(1)

        except Exception as e:
            print(e)
            
        finally:
            cnx.close()


make_NeedSolveCmd = make_NeedSolveCmd()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_11_002()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_11_006()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_11_007()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_11_011()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_11_003()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_11_004()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_11_005()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_11_008()
#make_NeedSolveCmd.Datasec_audit_mysql_protocol_11_009()
make_NeedSolveCmd.Datasec_audit_mysql_protocol_11_010()
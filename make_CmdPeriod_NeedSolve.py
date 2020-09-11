'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-11 11:44:43
LastEditors: YanQiaoYu
LastEditTime: 2020-09-11 17:06:36
FilePath: \Automated_MySQLAudit_Test\make_CmdPeriod_NeedSolve.py
'''
import mysql.connector
import sys
import os
from makeFactory import mySniff, GloConfig

class make_NeedSolveCmd:
    
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

    def make_02_COM_INIT_DB_use(self):
        FuncName = sys._getframe().f_code.co_name
        
        #1.开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #2.发送登陆报文
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )

            cnx.cmd_init_db("MySQL_Audit_Test")
            cnx.cmd_init_db("None")
        except:
            pass
        finally:
            thread.join()
            #3.保存抓包结果
            thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)  

            cnx.close()        

    def make_03_COM_QUERY_select(self):
        FuncName = sys._getframe().f_code.co_name
        
        #1.开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #2.发送登陆报文
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
            thread.join()
            #3.保存抓包结果
            thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)  

            cnx.close()        

    def make_03_COM_QUERY_create(self):
        

make_NeedSolveCmd = make_NeedSolveCmd()
'''
make_NeedSolveCmd.make_02_COM_INIT_DB_use()
'''
make_NeedSolveCmd.make_03_COM_QUERY_select()
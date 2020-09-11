'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-10 20:34:18
LastEditors: YanQiaoYu
LastEditTime: 2020-09-11 11:38:35
FilePath: \Automated_MySQLAudit_Test\make_ConnPeriod_HandShakeResponse.py
'''
import mysql.connector
import sys
import os
from makeFactory import mySniff, GloConfig

class make_ConnPeriod_HandShakeResponse:
    
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
        self.FileDir = "./Packet/02-ConnPeriod/02-HandShakeResponse/"
        #新建目录
        if os.path.exists(self.FileDir) and os.path.isdir(self.FileDir):
            pass
        else:
            os.makedirs(self.FileDir)      

        
    def make_ChineseUserName(self):
        FuncName = sys._getframe().f_code.co_name

        #开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()
        try:
            #发送登陆报文
            cnx = mysql.connector.connect(user="深信服", password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )
        except:
            pass
        finally:
            #保存抓包结果
            thread.join()
            thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName) 

        #cnx.close()         

    def make_RightUserNameAndPassword(self):
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

    def make_WrongUserName(self):
        FuncName = sys._getframe().f_code.co_name

        #开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        try:
            #发送登陆报文
            cnx = mysql.connector.connect(user="WrongName", password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )
        except:
            pass
        finally:
            #保存抓包结果
            thread.join()
            thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName) 

        #cnx.close()  

    def make_WrongCharSet(self):
        FuncName = sys._getframe().f_code.co_name

        #开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()
        try:
            #发送登陆报文
            cnx = mysql.connector.connect(user="WrongName", password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                charset = "utf32"
                                )
        except:
            pass
        finally:
            #保存抓包结果
            thread.join()
            thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName) 

            #cnx.close()          

    def make_SetTimeZone(self):
        FuncName = sys._getframe().f_code.co_name

        #开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            time_zone = "+8:00",
                            )

        #保存抓包结果
        thread.join()
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName) 

        cnx.close()       

    def make_SetSQLMode(self):
        FuncName = sys._getframe().f_code.co_name

        #开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            sql_mode = "NO_ZERO_DATE"
                            )

        #保存抓包结果
        thread.join()
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName) 

        cnx.close()   

    def make_ForceIPv6(self):
        FuncName = sys._getframe().f_code.co_name

        #开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            force_ipv6 = True,
                            )

        #保存抓包结果
        thread.join()
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName) 

        cnx.close()   

    def make_CompressPacket(self):
        FuncName = sys._getframe().f_code.co_name

        #开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            compress = True,
                            )

        #保存抓包结果
        thread.join()
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName) 

        cnx.close()  

    def make_PollNameAndPollSize(self):
        FuncName = sys._getframe().f_code.co_name

        #开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                            host=self.MySQLIP,
                            ssl_disabled='True',
                            pool_name = "TestPool",
                            pool_size = 2
                            )

        #保存抓包结果
        thread.join()
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName) 

        cnx.close()            

make_ConnPeriod_HandShakeResponse = make_ConnPeriod_HandShakeResponse()

make_ConnPeriod_HandShakeResponse.make_ChineseUserName()
make_ConnPeriod_HandShakeResponse.make_RightUserNameAndPassword()
make_ConnPeriod_HandShakeResponse.make_WrongUserName()
make_ConnPeriod_HandShakeResponse.make_WrongCharSet()
make_ConnPeriod_HandShakeResponse.make_SetTimeZone()
make_ConnPeriod_HandShakeResponse.make_SetSQLMode()
make_ConnPeriod_HandShakeResponse.make_ForceIPv6()
make_ConnPeriod_HandShakeResponse.make_CompressPacket()
make_ConnPeriod_HandShakeResponse.make_PollNameAndPollSize()


'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-09 10:01:15
LastEditors: YanQiaoYu
LastEditTime: 2020-09-10 15:42:09
FilePath: \Automated_MySQLAudit_Test\make_FrameWork_Basic.py
'''
import mysql.connector
import sys
import os
from makeFactory import mySniff, GloConfig

class make_FrameWork_Basic:
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

    #00结尾字符串：登录，确认服务器版本无异常
    #变长字符串：登录，auth-plugin-data-part-2字段无异常
    def make_00string_and_varString(self):
        FuncName = sys._getframe().f_code.co_name
        
        #1.开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #2.发送登陆报文
        cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                              host=self.MySQLIP,
                              ssl_disabled='True',
                              )
        cnx.close()

        thread.join()
        #3.保存抓包结果
        thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)


    #非法字符串：登录，账号填写中文
    def make_IllegalString(self):
        FuncName = sys._getframe().f_code.co_name
        
        #1.开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #2.发送登陆报文
        try:
            cnx = mysql.connector.connect(user="深信服", password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                )
        except:
            pass
        finally:
            thread.join()
            #3.保存抓包结果
            thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)

    #EOF结尾字符串：切换到不存在的数据库，Error Message解析无异常
    #定长字符串：切换到不存在的数据库，SQL status无异常
    #长度由其他字段确认的字符串：切换到不存在的数据库，报文正常即可
    #定长整数：切换到不存在的数据库，Err Response的报头解析无异常
    def make_EOFString_and_staticString_and_staticInt_and_controlledString(self):
        FuncName = sys._getframe().f_code.co_name
        
        #1.开启抓包
        thread = mySniff(self.timeout, self.filterString, FuncName)
        thread.start()

        #2.发送登陆报文
        try:
            cnx = mysql.connector.connect(user=self.MySQL_User, password=self.MySQL_Password,
                                host=self.MySQLIP,
                                ssl_disabled='True',
                                database='NoneExist',
                                )
        except:
            pass
        finally:
            thread.join()
            #3.保存抓包结果
            thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)     

    #变长整数：执行 show databases；长度解析无异常
    def make_VarInt(self):
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

            cmd = cnx.cursor()
            cmd.execute("show databases;")
        except:
            pass
        finally:
            thread.join()
            #3.保存抓包结果
            thread.saveResult(self.FileDir + FuncName + ".pcap", FuncName)  

            cmd.close()
            cnx.close()

make_FrameWork_Basic = make_FrameWork_Basic()
make_FrameWork_Basic.make_00string_and_varString()
make_FrameWork_Basic.make_IllegalString()
make_FrameWork_Basic.make_EOFString_and_staticString_and_staticInt_and_controlledString()
make_FrameWork_Basic.make_VarInt()


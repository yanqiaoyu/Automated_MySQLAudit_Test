'''
Author: YanQiaoYu
Github: https://github.com/yanqiaoyu?tab=repositories
Date: 2020-09-07 16:00:45
LastEditors: YanQiaoYu
LastEditTime: 2020-09-10 10:52:46
FilePath: \Automated_MySQLAudit_Test\test_FrameWork_basicVar.py
'''

import pytest
import mysql.connector

#测试内容：基本数据类型

#00结尾字符串：登录，确认服务器版本无异常
#EOF结尾字符串：切换到不存在的数据库，Error Message解析无异常
#变长字符串：登录，auth-plugin-data-part-2字段无异常
#定长字符串：切换到不存在的数据库，SQL status无异常
#长度由其他字段确认的字符串：切换到不存在的数据库，报文正常即可
#非法字符串：登录，账号填写中文

#定长整数：切换到不存在的数据库，Err Response的报头解析无异常
#变长整数：执行 show databases；长度解析无异常

'''
description: MySQL协议审计-基本框架-基本变量类型
param {type} 
return {type} 
'''
class TestFrameWorkBasicVar:

    '''
    description: 函数级别的setup，每个用例都会执行
    param {type}  None
    return {type} None
    '''
    def setup_function():
        #参考凯哥代码，每个用例执行前，清除审计缓存
        #TBD
        #clearAudit()
        print("用例执行前，执行这个")


    '''
    description: 函数级别的teardown，每个用例都会执行
    param {type}  None
    return {type} None
    '''
    def teardown_function():
        #无
        print("用例执行后，执行这个")
        pass


    '''
    description: 测试00结尾字符串与变长字符串这两种变量类型可以解析
    param {type} None
    return {type} None
    '''
    def test_Null_and_VarString():

        #1.回放报文
        replayPcap(xxxx)

        #2.调用协议审计功能
        forceAudit()

        #3.获取协议审计结果
        Result = getAuditResult()

        #4.断言验证审计结果
        assert Result.xxx = xxx
  

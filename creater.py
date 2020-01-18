#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2015 Futur Solo
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import sys
if sys.version_info.major < 3:
    print("FurtherLand needs as least Python3.3 or higher.")
    print("Please upgrade your Python version.")
    exit(1)
# use the to install all moudle
# python -m pip install tornado motor misaka mako pycurl feedgen  markdown pyotp bcrypt py-gfm
try:
    import tornado
except:
    print("Please install tornado Firstly")
    exit(1)

try:
    import motor
except:
    print("Please install motor Firstly")
    exit(1)

try:
    import misaka
except:
    print("Please install misaka Firstly")
    exit(1)

try:
    import mako
except:
    print("Please install mako Firstly")
    exit(1)

try:
    import pycurl
except:
    print("Please install pycurl Firstly")
    exit(1)

try:
    import feedgen
except:
    print("Please install feedgen Firstly")
    exit(1)

try:
    import markdown
except:
    print("Please install markdown Firstly")
    exit(1)

try:
    import pyotp
except:
    print("Please install pyotp Firstly")
    exit(1)

try:
    import bcrypt
except:
    print("Please install bcrypt Firstly")
    exit(1)
try:
    import mdx_gfm
except:
    print("Please install py-gfm")
    exit(1)

try:    
    import melody
    secret = melody.secret
    base = melody.base
    safeland = melody.safeland
    dev = melody.dev
    listen_ip = melody.listen_ip
    listen_port = melody.listen_port
    library = melody.library
    import pymongo
    credentials = ""
    if (library["auth"]):
        credentials=(library["user"]+ ":" + library["passwd"] + "@")
    DBClient= pymongo.MongoClient("mongodb://" + credentials + library["host"] + ":" +str(library["port"]) +"/")
    DBAdmin = DBClient[library["database"]]
    Preconfig = [
        {"_id":"Configs","site_name":"FurtherLand","site_url":"","nutrition_type":"summernight","site_description":"Nobody knows the Future, Why not fight up?","site_keywords":"FurtherLand, Python","trace_code":"<script></script>","configuration_name":"设置","crda_name":"管理","lobby_name":"首页","public_name":"文件上传","working_name":"创作","office_name":"控制台"}
    ]
    Configpreset=DBAdmin["Configs"]
    res = Configpreset.insert_many(Preconfig)
    preCounts = [
            {
                "_id": "Classes",
                "value": 0
            },
            {
                "_id": "Masters",
                "value": 1
            },
            {
                "_id": "Pages",
                "value": 0
            },
            {
                "_id": "Publics",
                "value": 0
            },
            {
                "_id": "Replies",
                "value": 0
            },
            {
                "_id": "Tags",
                "value": 0
            },
            {
                "_id": "Visitors",
                "value": 0
            },
            {
                "_id": "Writings",
                "value": 0
            },
            {
                "_id": "Writings_draft",
                "value": 0
            },
            {
                "_id": "Pages_draft",
                "value": 0
            },
            {
                "_id": "Replies_waiting_permit",
                "value": 0
            }
        ]
    Countspreset=DBAdmin["Counts"]
    res=Countspreset.insert_many(preCounts)
    preMasters = [
            {
                "_id": 1,
                "role":"master"
                ,
                "username":"admin" 
                #generate new password by listed commands:
                #password = "YOUR NEW PASSWORD"
                #bcrypt.hashpw(
                #hashlib.sha256(password.encode()
                #           ).hexdigest().encode(), bcrypt.gensalt())
                ,
                "email":"1@1.com"
                ,
                "password":"$2b$12$bQOD5kUzYTZYWRjDPgeVSeWxZlNuzOSlHXb3yjTW4pDclHyAxdNcm" #123456!
                ,
                "otp_key":""
                ,
                "last_login": 0
                ,
                "created": 0
                ,
                "homepage":"1.com"
                ,
                "emailmd5":"11111"
            }
        ]
    Masterspreset=DBAdmin["Masters"]
    res=Masterspreset.insert_many(preMasters)
except:
    print("Please Check Melody!")
    exit(1)
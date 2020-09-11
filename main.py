#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys
import time
import requests
import json
import hashlib
import threading
import os
from requests_toolbelt.multipart.encoder import MultipartEncoder
from optparse import OptionParser
import logging

logging.basicConfig(level=logging.INFO, filename='sbc.log', filemode='w', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('chardet.charsetprober')
logger.setLevel(logging.INFO)
logger = logging.getLogger('sbc')

parser = OptionParser()

def Usage():
    parser.add_option("-f", "--wav-file", help="audio wav filelist", action="store", type="string", dest="wavfile", default=None)
    parser.add_option("-p", "--product-id", help="sbc product id", action="store", type="string", dest="pid", default=None)
    parser.add_option("-k", "--public-key", help="sbc public key", action="store", type="string", dest="pkey", default=None)
    parser.add_option("-s", "--secret-key", help="sbc secret key", action="store", type="string", dest="skey", default=None)

class TokenGenerator(object):
    '''
         缓存token，获取token之后缓存，然后每次使用有效期内的token，设置定机器清空过期token
    '''
    token = ""

    def __init__(self, _productId, _publicKey, _secretKey):
        self.productId = _productId
        self.publicKey = _publicKey
        self.secretKey = _secretKey

    def getToken(self):
        # global token
        # read from token file
        token_file="token.txt"
        if os.path.exists(token_file):
            fd = open(token_file, "r")
            line = fd.readline()
            info = line.split(":")
            if len(info) == 2:
                etime = info[1]
                ctime = int(time.time())
                if (int(etime)-ctime > 60):
                    logger.info("get token from token file ...")
                    TokenGenerator.token = info[0]

        if TokenGenerator.token:
            return TokenGenerator.token
        #with self._value_lock:
        else:
            logger.info("get token from website ...")
            url = "http://api.talkinggenie.com/api/v2/public/authToken"
            timeStamp = str(int(round(time.time() * 1000)))
            sign = hashlib.md5(
                (self.publicKey + self.productId + timeStamp + self.secretKey).encode('utf8')).hexdigest()
            # 请求头
            data = {
                "productId": self.productId,
                "publicKey": self.publicKey,
                "sign": sign,
                "timeStamp": timeStamp
            }
            headers = {
                'Content-Type': "application/json"
            }
            response = requests.post(url=url, headers=headers, data=json.dumps(data))
            if response.status_code == 200:
                TokenGenerator.token = response.json()["result"].get("token")
                logger.info("token:%s" % TokenGenerator.token)
                expireTime = response.json()["result"].get("expireTime")
                logger.info("expire:%s" % expireTime)
                with open(token_file, "w+") as out:
                    out.write(TokenGenerator.token + ":" + str(round(int(expireTime)/1000)))
            return TokenGenerator.token

class AsrGenerator(threading.Thread):
    def __init__(self, _productId, _token, _index, _wav_file):
        threading.Thread.__init__(self)
        self.productId = _productId
        self.token = _token
        self.wav_file = _wav_file
        self.index = _index

    def run(self):
        result = self.recognition()
        logger.info("index:%d, wav file:%s, result:%s" % (self.index, self.wav_file, result))

    def getResult(self, id):
        result = ""
        url = "https://api.talkinggenie.com/smart/sinspection/api/v2/getTransResult"
        # 请求头
        headers = {
            'Content-Type': "application/json;charset=UTF-8",
            'Accept': "application/json;charset=UTF-8",
            'X-AISPEECH-TOKEN': self.token,
            'X-AISPEECH-PRODUCT-ID': self.productId
        }
        data={}
        data["dialog"] = {}
        data["dialog"]["productId"] = self.productId
        data["metaObject"] = {}
        data["metaObject"]["fileId"] = id
        retry=0
        while retry < 20:
            time.sleep(1)
            try:
                response = requests.post(url=url, headers=headers, data=json.dumps(data))
            except:
                logger.error("get result exception ...")
                continue
            else:
                if response.status_code == 200:
                    #print(response.text)
                    info = response.json()
                    if info["code"] == 200:
                        info_status = info["data"]["status"]
                        if info_status == "TRANSFERING":
                            logger.debug("status is transfering, continue ...")
                            continue
                        elif info_status == "SUCCEED":
                            result = ""
                            for part in info["data"]["result"]:
                                result += part["text"]
                            break
                        else:
                            logger.error("get result failed, status: %s" % info_status)
                            break
                    else:
                        logger.error("get result failed, code: %d" % info["code"])
                        break
                else:
                    logger.error("get result failed, response code: %d, text: %s,", response.status_code, response.text)
                    break

        return result


    def recognition(self):
        url = "http://api.talkinggenie.com/smart/sinspection/api/v1/fileUpload"

        # 请求头
        param = {}
        param["dialog"] = {}
        param["dialog"]["productId"] = self.productId
        param["metaObject"] = {}
        param["metaObject"]["recordId"] = self.wav_file
        param["metaObject"]["priority"] = 100
        #param["metaObject"]["speechSeparate"] = True
        #param["metaObject"]["speakerNumber"] = 1
        encoder = MultipartEncoder(
            fields={
                'param': json.dumps(param, sort_keys=True, indent=4, separators=(',', ': ')),
                'file': (self.wav_file, open(self.wav_file, 'rb'), 'application/octet-stream')
            }
        )
        headers = {
            'Content-Type': encoder.content_type,
            'Accept': "application/json",
            'X-AISPEECH-TOKEN': self.token,
            'X-AISPEECH-PRODUCT-ID': self.productId
        }
        logger.info("recognition [%s] ..." % self.wav_file)
        print("recognition [%s] ..." % self.wav_file)
        retry = 0
        while retry < 3:
            retry += 1
            try:
                response = requests.post(url=url, headers=headers, data=encoder)
            except:
                logger.error("upload [%s] file exception" % (self.wav_file))
                time.sleep(1)
                continue
            else:
                if response.status_code == 200:
                    result = response.json()
                    if result["code"] == 200:
                        fileId = result["data"]["fileId"]
                        return self.getResult(fileId)
                    else:
                        logger.error("upload [%s] failed, result code: %d, msg: %s, status: %s" % (self.wav_file, result["code"], result["msg"], result["data"]["status"]))
                else:
                    logger.error("upload [%s] failed, response code: %d" % (self.wav_file, response.status_code))

        return ""

if __name__ == "__main__":
    Usage()
    (options, args) = parser.parse_args(sys.argv)
    if options.wavfile == None:
        logger.error("parser error, wav file is null")
        exit(-1)
    if options.pid == None:
        logger.error("parser error, product id is null")
        exit(-1)
    if options.pkey == None:
        logger.error("parser error, public key is null")
        exit(-1)
    if options.skey == None:
        logger.error("parser error, secret key is null")
        exit(-1)
    logger.info("main start")
    #token
    tokenGenerator = TokenGenerator(options.pid, options.pkey, options.skey)
    token = tokenGenerator.getToken()
    if token == "":
        logger.error("get token failed")
        exit(-2)
    threadlist = []
    with open(options.wavfile, "r") as fd:
        index = 1
        for wavfile in fd:
            #asr
            t = AsrGenerator(options.pid, token, index, wavfile.rstrip('\n'))
            threadlist.append(t)
            index+=1
    for t in threadlist:
        t.start()
        time.sleep(4)
    for t in threadlist:
        t.join()
    logger.info("main over")
    print("finished")




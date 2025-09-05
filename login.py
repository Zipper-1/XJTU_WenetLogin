import json
import os
import requests
import logging
from urllib import parse
from typing import Literal
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad,pad
except ModuleNotFoundError:
    print("please install pycryptodome")
    
logging.DEBUG


class IHarbourNet:
    class LoginError(Exception):
        def __init__(self, *args: object) -> None:
            super().__init__(*args)

    class AlreadyOnlineError(Exception):
        def __init__(self, *args) -> None:
            super().__init__(*args)

    def __init__(self,auth_base_url='10.184.6.32'):
        if not (auth_base_url.startswith('http://') or auth_base_url.startswith('https://')):
            auth_base_url='http://'+auth_base_url
        self.auth_base_url=parse.urlparse(auth_base_url).geturl()
        self._client=requests.Session()
        self._client.headers["user-agent"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        self.__isOnline=False

    @property
    def isOnline(self):
        return self.__isOnline
    
    def _decryptMsg(self,message):
        key=iv=b'1234567890000000'
        cipher=AES.new(key,AES.MODE_CBC,iv=iv)
        data_raw=bytes.fromhex(message)
        data_decryptd=cipher.decrypt(data_raw)
        data=json.loads(unpad(data_decryptd,AES.block_size,"pkcs7").decode().replace('\\n','').replace('\\"','"').replace('\\\\','\\').removeprefix('"').removesuffix('"'))
        return data
        
    def _encryptMsg(self,message):
        if isinstance(message,str):
            message=message.encode()
        key=iv=b'1234567890000000'
        cipher=AES.new(key,AES.MODE_CBC,iv=iv)
        message_padded=pad(message,AES.block_size,'pkcs7')
        data_encrypted=cipher.encrypt(message_padded)
        data_encryptedHex=data_encrypted.hex()
        return data_encryptedHex

    def _getConfig(self):
        if hasattr(self,'_config'):
            return self._config
        else:
            config_path='/portal-conversion/api/v3/portal/get/jsonConfig?filename=configration.json'
            config_raw=self._client.post(self.auth_base_url+config_path).text
            config=self._decryptMsg(config_raw)
            self._config=config
            return config

    def _getRedirectUrl(self,url_default):
        res=self._client.get(url_default,allow_redirects=False,proxies={'http': None, 'https': None})
        redirect_url = res.headers.get('Location')
        print(redirect_url)
        self._client.get(redirect_url)
        return redirect_url

    def _check_authsheet_valid(self,data):
        if data:
            if not data=='':
                return True
        return False

    def testOnline(self):
        testurl=self._getConfig()['configrations'][0]['systemConfig']['detectJsUrl']
        try:
            res=self._client.get(url=testurl,allow_redirects=False,timeout=3)
            if res.status_code==200:
                return True
            return False
        except (requests.exceptions.Timeout,requests.exceptions.ConnectionError) as e:
            return False 
        except Exception:
            print('error testing net')
            return False

    def login(self,net_id:str,password:str|int,os_type:Literal ['PC','ANDROID','IOS','unknow']='PC',end_with_doble_XJTU=False,loggedin_ok=True,ignore_auth_error=False):
        self.__isOnline=self.testOnline()
        if self.__isOnline:
            if not loggedin_ok:
                raise self.AlreadyOnlineError()
            else:
                pass
                logging.warning('Host is already online, if you want to skip login, set loggedin_ok=False')
            #return True
        if (not self._check_authsheet_valid(net_id)) or (not self._check_authsheet_valid(password)):
            logging.error('net id & password must not be empty.')
            raise self.LoginError('net id & password must not be empty.')
        if net_id.endswith('@xjtu') and not end_with_doble_XJTU:
            logging.warning('net id subfix "@xjtu" will add automaticly, if you are sure your net id ends with @xjtu, pass end_with_doble_XJTU=True')
        else:
            net_id+='@xjtu'
        if isinstance(password,int):
            password=str(password)
        login_path='/portal-conversion/api/v3/portal/connect'
        try:
            login_conf=self._getConfig()
            info_url=login_conf['configrations'][0]['systemConfig']['autoRedirectUrl']
        except Exception as e:
            logging.warning('failed to get default redirect&infomation url, use "http://2.2.2.2"')
            info_url="http://2.2.2.2"
        #redirect_url=redirect_url_default
        redirect_url=self._getRedirectUrl(info_url)
        data={'deviceType':os_type,'redirectUrl':redirect_url,'webAuthUser':net_id,'webAuthPassword':password}
        data_encrypted=self._encryptMsg(json.dumps(data))
        res=self._client.post(self.auth_base_url+login_path,data=data_encrypted,headers={'content-type':'application/json'})
        resobj=self._decryptMsg(res.json())
        print(resobj)
        logging.debug(resobj)
        if resobj['statusCode']==200:
            logging.info("log in ")
            self.__isOnline=True
            return True
        else:
            info=resobj['errorDescription']
            logging.error(info)
            if not ignore_auth_error:
                logging.warning('If this Exception is not intended please set ignore_auth_error=True')
                raise self.LoginError(info)
            return False



        

        


if __name__=='__main__':
    log=IHarbourNet()
    if not log.testOnline():
        user=os.getenv('NETID')
        pswd=os.getenv('NETPASS')
        #print(log._getConfig()['configrations'][0]['systemConfig'])
        log.login(user,pswd)
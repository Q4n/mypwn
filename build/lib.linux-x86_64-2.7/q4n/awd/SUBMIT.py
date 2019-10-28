# -*- coding:utf-8 -*-
import requests
class SUBMIT:
    """
    利用requests.post方法来提交flag
    s=SUBMIT("http://local/submit","mytoken","answer","TOKEN")
    s.submit("flag")
    """
    def __init__(self,url,token_value,flag_key='answer',token_key='TOKEN'):
        self.token_value=token_value
        self.url=url
        self.flag_key=flag_key
        self.token_key=token_key    
    def submit(self,flag_value):
        self.data = {self.flag_key: flag_value, self.token_key: self.token_value}
        try:   
            state = requests.post(self.url, data=self.data, timeout=3, verify=False).text
        except requests.Timeout:
            state = 'requests timeout'
        finally:
            print state
            print "--------------------- END ---------------------\n"
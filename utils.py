# -*- coding: utf-8 -*-
import hashlib
import base64
def md5Encode(str):
    # 参数必须是byte类型，否则报Unicode-objects must be encoded before hashing错误
    m = hashlib.md5(str.encode(encoding='utf-8'))
    return m.hexdigest()

def base64Encode(str):
    return base64.b64encode(str.encode(encoding="utf-8")).decode()

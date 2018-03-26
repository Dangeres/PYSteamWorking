def get_auth_code(secret):
    t = int(time.time()/30)
    key = base64.b64decode(secret)
    t = t.to_bytes(8, 'big')
    digester = hmac.new(key, t, hashlib.sha1)
    signature = digester.digest()
    signature = list(signature)
    start = signature[19]&0xf
    fc32 = bytes_to_int(signature[start:start+4])
    fc32 &= 2147483647
    fullcode = list('23456789BCDFGHJKMNPQRTVWXY')
    length = len(fullcode)
    code = ''
    for i in range(5):
        code += fullcode[fc32%length]
        fc32 //= lengt
    return code
    
if __name__ == '__main__':
    print(get_auth_code('cnOgv/KdpLoP6Nbh0GMkXkPXALQ='))

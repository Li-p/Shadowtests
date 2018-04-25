Shadowtests
===========

Test connectivity to a Shadowsocks server

#Usage

shadowtests.py IP/Domain Port Password Method

###Optional switches:

* -S, --simple

   Simple Mode.   
   Try to access Google's [Generate_204 page](http://www.gstatic.com/generate_204) via SS server   
   print 1 if it is accessible, otherwise 0

* -v, --verbose

   Show debug info

### Compatibility
Python 2.7+ or 3.5+

Examples:

    ./shadowtests.py example.com 8443 123456 aes-256-cfb
    [2018-04-22 11:49:24,672] Shadowsocks Server: example.com 8443 123456 aes-256-cfb
    [2018-04-22 11:49:24,672] Establishing connection to Shadowsocks server ss.shell.one:443
    [2018-04-22 11:49:24,911] Accessing Google
    [2018-04-22 11:49:24,999] loading libcrypto from libcrypto.so.1.0.0
    [2018-04-22 11:49:25,600] OK
    [2018-04-22 11:49:25,600] Accessing www.icanhazip.com
    [2018-04-22 11:49:26,365] OK: 35.194.248.137   

---
    ./shadowtests.py ss.shell.one 443 Wrongpass aes-256-cfb
    [2018-04-25 12:05:23,136] Shadowsocks Server: ss.shell.one 443 Wrongpass aes-256-cfb
    [2018-04-25 12:05:23,136] Establishing connection to Shadowsocks server ss.shell.one:443
    [2018-04-25 12:05:23,379] Accessing Google
    [2018-04-25 12:05:23,471] loading libcrypto from libcrypto.so.1.0.0
    [2018-04-25 12:05:23,889] Shadowsocks server closed the connection unexpctedly. Wrong password?
    [2018-04-25 12:05:23,890] Unable to access Google's generate_204 page
    [2018-04-25 12:05:23,890] Accessing www.icanhazip.com
    [2018-04-25 12:05:24,445] Shadowsocks server closed the connection unexpctedly. Wrong password?
---
    ./shadowtests.py example.com 8443 123456 aes-256-cfb --simple
    1
    
# API

You may also integrate this program into your own by importing the ShadowTest Class

For example:

```python
from shadowtests import ShadowTest
obj = ShadowTest("example.com", 8443, "123456", "aes-256-cfb")
print(obj.generate_204())
# True or False

# Access http://www.icanhazip.com/
print(obj.icanhazip())
# True or False
# if True, that website's response i set to obj.ip_result

print(obj.ip_result)
# 123.123.123.123

# send customized TCP packet
# Asssume remote server 111.111.111 is listening on port 1000 and will reapsond with "Pong" upon receiving "Ping"
resp = obj.tcp_relay(port=1000, payload=b"Ping", ipv4="111.111.111.111")
print(resp)
# b"Pong"
```

# Licence
Apache 2.0   
This program includes code from the original Shadowsocks project

# Copyright
Peng Li 2018   
clowwindy 2012-2015
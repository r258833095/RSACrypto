
功能：
Swift版，RSA字符串公钥加密，输出16进制字符串结果。
使用SecKey，无需引入openSSL，支持iOS9以上。

使用方法：
let key : NSString = "MIGfMA0....略....IwIDAQAB";
let str : NSString? = RSACrypto.encryptString(content: "123456", pubKey: key) as NSString?
NSLog("%@", str ?? "err")

参考资料：
swift-RSA(一)   
https://www.jianshu.com/p/d2cb314d30ec
iOS RSA加密算法  
https://www.jianshu.com/p/90c6ac200888
[Swift] 指针UnsafePointer  
https://www.jianshu.com/p/e90393ba2aea

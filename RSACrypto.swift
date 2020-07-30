//
//  RSACrypto.swift
//  RSACrypto
//
//  Created by 斌 on 2020/7/29.
//  Copyright © 2020 斌. All rights reserved.
//

import Foundation

class RSACrypto: NSObject {
    class func encryptString(content: String, pubKey: NSString) -> String? {
        let contentData: NSData = (content.data(using: String.Encoding.utf8)! as NSData)
        let data : NSData? = encryptData(content: contentData, pubKey: pubKey)
        if data != nil {
            let ret = dataToHexStr(data: data!)
            return ret
        }
        return nil
    }
    
    class func encryptData(content: NSData?, pubKey: NSString?) -> NSData? {
        
        if (content == nil || pubKey == nil){
            return nil;
        }
        
        //Public Key
        let keyRef : SecKey? = addPublicKey(key: pubKey!)
        if (keyRef == nil) {
            return nil;
        }
        
        return encryptData(data: content!, keyRef: keyRef!)
    }
    
    class func addPublicKey(key: NSString) -> SecKey? {
        
        // This will be base64 encoded, decode it.
        let data = NSData(base64Encoded: key as String, options: NSData.Base64DecodingOptions(rawValue: NSData.Base64DecodingOptions.ignoreUnknownCharacters.rawValue))
        if (data == nil){
            return nil
        }
        
        //a tag to read/write keychain storage
        let tag : NSString = "RSA_PubKey"
        let d_tag : NSData = NSData(bytes: tag.utf8String, length: tag.length)
        
        // Delete any old lingering key with the same tag
        let publicKey : NSMutableDictionary = NSMutableDictionary()
        publicKey.setObject(kSecClassKey, forKey: kSecClass as! NSCopying)
        publicKey.setObject(kSecAttrKeyTypeRSA, forKey: kSecAttrKeyType as! NSCopying)
        publicKey.setObject(d_tag , forKey: kSecAttrApplicationTag as! NSCopying)
        SecItemDelete(publicKey)
        
        
        // Add persistent version of the key to system keychain
        publicKey.setObject(data!, forKey: kSecValueData as! NSCopying)
        publicKey.setObject(kSecAttrKeyClassPublic, forKey:kSecAttrKeyClass as! NSCopying)
        publicKey.setObject(NSNumber(booleanLiteral: true), forKey: kSecReturnPersistentRef as! NSCopying)
        
        var status : OSStatus = SecItemAdd(publicKey, nil)
        if ((status != noErr) && (status != errSecDuplicateItem)) {
            return nil
        }
        
        publicKey.removeObject(forKey: kSecValueData)
        publicKey.removeObject(forKey: kSecReturnPersistentRef)
        publicKey.setObject(NSNumber(booleanLiteral: true), forKey: kSecReturnRef as! NSCopying)
        publicKey.setObject(kSecAttrKeyTypeRSA, forKey: kSecAttrKeyType as! NSCopying)
        
        // Now fetch the SecKeyRef version of the key
        var keyRef : AnyObject?
        status = SecItemCopyMatching(publicKey, &keyRef)
        if(status != noErr){
            return nil;
        }
        return (keyRef as! SecKey)
    }
    
    
    class func encryptData(data: NSData?, keyRef: SecKey?) -> NSData? {
        
        guard data != nil && keyRef != nil else {
            return nil
        }
        
        var resData : NSData? = nil
        if #available(iOS 10.0, *) {
            var error: Unmanaged<CFError>?
            resData =  SecKeyCreateEncryptedData(keyRef!, SecKeyAlgorithm.rsaEncryptionPKCS1, data! as CFData, &error)
            print("res = \(String(describing: error?.takeUnretainedValue().localizedDescription))")
        } else{
            
            // Fallback on earlier versions
            let blockLen =  SecKeyGetBlockSize(keyRef!)
            var outBuf = [UInt8](repeating: 0, count: blockLen)
            var outBufLen:Int = blockLen
            
            let status: OSStatus = SecKeyEncrypt(keyRef!, SecPadding.PKCS1, data!.bytes.assumingMemoryBound(to: UInt8.self), data!.count, &outBuf, &outBufLen)
            if status == noErr {
                resData = NSData(bytes: outBuf, length: outBufLen)
            }
        }
        
        if resData != nil {
            return resData
        }
        return nil
    }
    
    class func dataToHexStr(data: NSData?) -> String? {
        
        guard (data != nil) else {
            return nil
        }
        
        let string : NSMutableString = NSMutableString(capacity: data!.length);
        data?.enumerateBytes({(bytes, byteRange, stop) in
            let dataBytes : UnsafeRawPointer = bytes
            for idx in 0...byteRange.length - 1 {
                
                let hexStr = NSString(format: "%x", (dataBytes.load(fromByteOffset: idx, as: UInt8.self)) & 0xff)
                if (hexStr.length == 2) {
                    string.append(hexStr as String)
                } else {
                    string.appendFormat("0%@", hexStr)
                }
            }
        })
        
        return string as String
    }
    
    
    
    
}

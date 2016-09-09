package com.hhh.shiro.util;


import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;

/**
 * 密码加密工具类
 * @author mars.zhong
 *
 */
public class EncryptHelper {
	public static final String HASH_ALGORITHM = "md5";
	public static final int HASH_INTERATIONS = 2;
	
	/**
	 * 产生随机盐
	 * @return
	 */
	public static String randomNumberSalt() {
		RandomNumberGenerator randomNumberGenerator =  
			     new SecureRandomNumberGenerator(); 
		
		return randomNumberGenerator.nextBytes().toHex();
	}
	
	/**
	 * 利用盐对字符串进行加密
	 * @param str
	 * @param salt
	 * @return
	 */
	public static String entrypt(String str, String salt) {
		return new SimpleHash(  
				HASH_ALGORITHM,  str,  
                ByteSource.Util.bytes(salt),  
                HASH_INTERATIONS).toHex();
	}
}

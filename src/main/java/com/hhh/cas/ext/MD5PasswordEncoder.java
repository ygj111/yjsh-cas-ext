package com.hhh.cas.ext;

import org.jasig.cas.authentication.handler.PasswordEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hhh.shiro.util.EncryptHelper;

public class MD5PasswordEncoder implements PasswordEncoder {
	private final Logger logger = LoggerFactory.getLogger(MD5PasswordEncoder.class);
	
	private String salt;
	
	public String encode(String password) {		
		String encodePwd =  EncryptHelper.entrypt(password, salt);
		logger.info("Encode password: " + encodePwd);
		return encodePwd;
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	
}

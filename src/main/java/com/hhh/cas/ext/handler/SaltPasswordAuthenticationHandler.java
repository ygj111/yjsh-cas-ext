package com.hhh.cas.ext.handler;

import java.security.GeneralSecurityException;
import java.util.Map;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.validation.constraints.NotNull;

import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

import com.hhh.cas.ext.MD5PasswordEncoder;

/**
 * 增加处理加Salt后的password的数据库访问类
 * @author mars.zhong
 *
 */
public class SaltPasswordAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {
	private static Logger logger = LoggerFactory.getLogger(SaltPasswordAuthenticationHandler.class);
	@NotNull
    private String sql;
	
	@Override
	protected HandlerResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential)
			throws GeneralSecurityException, PreventedException {
		
		final String username = credential.getUsername();
		logger.info("============Login user name is :" + username );
		
		
		try {
			final Map<String, Object> values = getJdbcTemplate().queryForMap(this.sql, username);
			String dbPassword = (String) values.get("password");
            String salt = (String) values.get("salt");
            
           ( (MD5PasswordEncoder)getPasswordEncoder()).setSalt(salt);
           final String encryptedPassword = getPasswordEncoder().encode(credential.getPassword());
           
            if (!dbPassword.equals(encryptedPassword)) {
                throw new FailedLoginException("Password does not match value on record.");
            }
        } catch (final IncorrectResultSizeDataAccessException e) {
            if (e.getActualSize() == 0) {
                throw new AccountNotFoundException(username + " not found with SQL query");
            } else {
                throw new FailedLoginException("Multiple records found for " + username);
            }
        } catch (final DataAccessException e) {
            throw new PreventedException("SQL exception while executing query for " + username, e);
        }
		
//		return createHandlerResult(credential, new SimplePrincipal(username), null);
		 return createHandlerResult(credential, this.principalFactory.createPrincipal(username), null);
	}
	
	/**
     * @param sql The sql to set.
     */
    public void setSql(final String sql) {
        this.sql = sql;
    }
}

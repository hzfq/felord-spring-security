package cn.felord.security.jwt.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author huzhifengqing@qq.com
 * @since 2022/4/17 21:38
 */
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint,
        InitializingBean {
    // ~ Instance fields
    // ================================================================================================

    private String realmName;

    // ~ Methods
    // ========================================================================================================

    public void afterPropertiesSet() {
//        Assert.hasText(realmName, "realmName must be specified");
        setRealmName("username");
    }

    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        response.addHeader("WWW-Authenticate", "Basic realm=\"" + realmName + "\"");
        response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
    }

    public String getRealmName() {
        return realmName;
    }

    public void setRealmName(String realmName) {
        this.realmName = realmName;
    }
}

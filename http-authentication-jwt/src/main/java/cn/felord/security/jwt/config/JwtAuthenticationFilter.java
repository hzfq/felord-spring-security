package cn.felord.security.jwt.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * JWT认证过滤器
 *
 * @author huzhifengqing@qq.com
 * @see org.springframework.security.web.authentication.www.BasicAuthenticationFilter
 * @since 2022/4/17 20:02
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final String AUTHORIZATION_PREFIX = "Bearer ";
    private AuthenticationEntryPoint authenticationEntryPoint = new BasicAuthenticationEntryPoint();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String authentication = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (StringUtils.hasText(authentication) && authentication.startsWith(AUTHORIZATION_PREFIX)) {
                String jwtToken = authentication.substring(authentication.indexOf(AUTHORIZATION_PREFIX));
                if (StringUtils.hasText(jwtToken)) {
                    logger.info("token: " + jwtToken);
                    try {
                        authenticationJwt(request, response, jwtToken);
                    } catch (AuthenticationException failed) {
                        SecurityContextHolder.clearContext();
                        //remember-me
                        onUnsuccessfulAuthentication(request, response, failed);
                        this.authenticationEntryPoint.commence(request, response, failed);
                        return;
                    }
                }
            }
        }
        filterChain.doFilter(request, response);
    }

    /**
     * 验证jwt token
     */
    private void authenticationJwt(HttpServletRequest request, HttpServletResponse response, String jwtToken) {
        //1. verify token
        if (jwtToken.length() > 0) {
            //2. 从token中取出用户名
            //3. 从缓存中取出用户名关联的token
            //3.1 缓存中没有token
//            throw new CredentialsExpiredException("token is expired");

            //4. 验证access_token是否相同
            //4.1 若不相同
//            throw new BadCredentialsException("token is not matched");

            //取出用户名关联的角色
            List<String> roles = new ArrayList<>();
            List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(roles.toArray(new String[0]));
            //构建用户认证的authentication
            User user = new User("username", "[PROTECTED]", authorities);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(user, null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            //放入安全上下文中
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Token {} is invalid", jwtToken);
            }
            throw new BadCredentialsException("token is invalid");
        }
    }

    protected void onUnsuccessfulAuthentication(HttpServletRequest request,
            HttpServletResponse response, AuthenticationException failed) throws IOException {
    }
}

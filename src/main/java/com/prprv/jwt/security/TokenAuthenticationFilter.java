package com.prprv.jwt.security;

import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * @author Yoooum
 */
@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {
    private final TokenProvider tokenProvider;
    private final UserDetailsServiceImpl userDetailsService;

    public TokenAuthenticationFilter(TokenProvider tokenProvider, UserDetailsServiceImpl userDetailsService) {
        this.tokenProvider = tokenProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            JWTClaimsSet claimsSet = tokenProvider.parseToken(token);
            if (!tokenProvider.isExpiredToken(claimsSet)) {
                String username = claimsSet.getSubject();
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                System.out.println(userDetails);
                var authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                // 获取 request.getRemoteAddr() 到 authenticationToken 中
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                System.out.println(authenticationToken);
                // 更新上下文中的认证信息，将身份认证令牌写入上下文，
                // 这样就可以在 Controller 中使用 @AuthenticationPrincipal 获取当前用户信息。
                // 参数为 null 时，表示当前用户未登录，触发 InsufficientAuthenticationException (401) 异常
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            } else {
                System.out.println("token is expired");
            }
        } else {
            System.out.println("authentication failed");
        }
        filterChain.doFilter(request, response);
    }
}

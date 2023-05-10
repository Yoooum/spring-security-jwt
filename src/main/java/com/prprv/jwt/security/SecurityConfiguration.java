package com.prprv.jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author Yoooum
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    private final TokenAuthenticationEntryPoint entryPoint;
    private final TokenAccessDeniedHandler deniedHandler;
    private final TokenAuthenticationFilter tokenFilter;

    public SecurityConfiguration(TokenAuthenticationEntryPoint entryPoint, TokenAccessDeniedHandler deniedHandler, TokenAuthenticationFilter tokenFilter) {
        this.entryPoint = entryPoint;
        this.deniedHandler = deniedHandler;
        this.tokenFilter = tokenFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 关闭csrf
                .csrf().disable()
                // 关闭默认页面，自己实现登入、登出
                .formLogin().disable()
                .httpBasic().disable()
                .logout().disable()

                // 请求认证
                .authorizeHttpRequests()
                // 不需要身份认证的请求
                .requestMatchers("/api/auth/authorize","/api/auth/token").anonymous()
                // 其他所有请求都需要登录
                .anyRequest().authenticated()
                .and()
                // 异常处理
                .exceptionHandling()
                // 未登录时，返回401
                .authenticationEntryPoint(entryPoint)
                // 无权限时，返回403
                .accessDeniedHandler(deniedHandler)
                .and()
                // Token过滤器
                .addFilterBefore(tokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

package com.prprv.jwt.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.ErrorResponse;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Yoooum
 */
@Component
public class TokenAccessDeniedHandler implements AccessDeniedHandler {
    private final ObjectMapper objectMapper;

    public TokenAccessDeniedHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json;charset=UTF-8");
        Map<String,String> error = new HashMap<>();
        error.put("error", accessDeniedException.getLocalizedMessage());
        response.getWriter().write(objectMapper.writeValueAsString(error));
    }
}

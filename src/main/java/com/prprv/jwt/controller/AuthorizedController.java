package com.prprv.jwt.controller;

import com.nimbusds.jwt.JWTClaimsSet;
import com.prprv.jwt.security.TokenProvider;
import jakarta.annotation.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Yoooum
 */
@RequestMapping("/api/auth")
@RestController
public class AuthorizedController {
    @Resource
    private TokenProvider tokenProvider;
    @PostMapping("/authorize")
    public Object createToken(@RequestBody String refreshToken) {
        JWTClaimsSet claimsSet = tokenProvider.parseToken(refreshToken);
        boolean expiredToken = tokenProvider.isExpiredToken(claimsSet);
        if (expiredToken) {
            return "token expired";
        }
        List<String> authorities = new ArrayList<>();
        authorities.add("user:write");
        authorities.add("user:read");
        Map<String,Object> claims = claimsSet.getClaims();
        claims.put("authorities", authorities);
        return tokenProvider.createToken("1", claims);
    }

    record SignIn(String username,String password){}
    @PostMapping("/token")
    public Object createToken(@RequestBody SignIn signIn) {
        if (signIn.username.equals("admin") && signIn.password.equals("123456")) {
            return tokenProvider.createToken(signIn.username, new HashMap<>());
        }
        Map<String,Object> error = new HashMap<>();
        error.put("error", "Invalid username or password");
        return error;
    }

    @GetMapping("/user")
    public User user(@AuthenticationPrincipal User user) {
        System.out.println(user);
        return user;
    }
}

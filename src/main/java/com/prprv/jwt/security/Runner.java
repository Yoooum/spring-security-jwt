package com.prprv.jwt.security;

import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.annotation.Resource;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;

/**
 * @author Yoooum
 */
@Component
public class Runner implements CommandLineRunner {
    @Resource
    private TokenProvider tokenProvider;

    @Override
    public void run(String... args) throws Exception {
        HashMap<String, Object> map = new HashMap<>();
        map.put("id", "1");
        map.put("name", "Yoooum");
        map.put("email", "Yoooum@qq.com");
        map.put("role", "admin");

        TokenProvider.Token token = tokenProvider.createToken("1", map);
        JWTClaimsSet accessTokenSet = tokenProvider.parseToken(token.accessToken());
        JWTClaimsSet refreshTokenSet = tokenProvider.parseToken(token.refreshToken());

        System.out.println("\nAccess token: " + token.accessToken());
        System.out.println("Payload " + accessTokenSet.toPayload());

        System.out.println("\nRefresh token: " + token.refreshToken());
        System.out.println("Payload " + refreshTokenSet.toPayload());

        System.out.println();

        boolean computed = true;
        while (computed) {
            if (tokenProvider.isExpiredToken(accessTokenSet)) {
                System.out.println("Access token expired");
                computed = false;
            } else {
                long valid = (accessTokenSet.getExpirationTime().getTime() - new Date().getTime()) / 1000;
                System.out.println("Access token valid for " + valid + " seconds");
            }
            Thread.sleep(1000);
        }
    }
}


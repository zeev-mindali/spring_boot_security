package com.jb.security.JWT;

import com.google.common.net.HttpHeaders;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
@Data
@NoArgsConstructor
public class JwtConfig {
    @Value("${application.jwt.secretKey}")
    private String secretKey;
    @Value("${application.jwt.tokenPrefix}")
    private String tokenPrefix;
    @Value("${application.jwt.tokenExpirationAfterDays}")
    private int tokenExpirationAfterDays;

    @Bean
    public SecretKey getSecretKey(){
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String getAuthorizationHeader(){
        return HttpHeaders.AUTHORIZATION;
    }
}

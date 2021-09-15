package com.jb.security.JWT;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JwtTokenVerifier extends OncePerRequestFilter {
    //execute the filter only once for every single request comming from the client
    private final JwtConfig jwtConfig;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());
        //if we have incorrect token
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())){
            filterChain.doFilter(request,response);
            return;
        }

        //JWT -> Jeson Web Token   JWS -> Json Web (token) Signed done by .compact()
        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");
        try{
            Jws<Claims> clamisJws = Jwts.parser().setSigningKey(jwtConfig.getSecretKey()).parseClaimsJws(token);
            Claims body = clamisJws.getBody();
            String username = body.getSubject();
            var authorities = (List<Map<String,String>>) body.get("authorities");
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(item -> new SimpleGrantedAuthority(item.get("authority")))
                    .collect(Collectors.toSet());
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,null, simpleGrantedAuthorities
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException err){
            throw new IllegalStateException(String.format("Token %s can not be trusted",token));
        }
        filterChain.doFilter(request,response);
    }
}

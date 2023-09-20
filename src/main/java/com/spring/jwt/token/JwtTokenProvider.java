package com.spring.jwt.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;

/**
 * Jwt Token 생성, 인증, 권한부여, 유효성검사 , pk 추출 등의 기능을 제공하는 클래스
 */
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private long tokenValidTime = 30 * 60 * 1000L; // 토큰 유효시간 30분
    private final UserDetailsService userDetailsService;

    private String secretKey = "codemind12#$";

    private Key getSecretKey(String secretKey) {
        byte[] KeyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(KeyBytes);
    }

/*    *//**
     * 객체 초기화, secretKey를 Base64로 인코딩
     *//*
    @PostConstruct
    protected void init() {
        secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        //Base64.getEncoder().encodeToString(secretKey.getBytes());
    }*/

    /**
     * 토큰 생성
     *
     * @param userId String userId
     * @param auth   List<String> auth
     * @return String token
     */
    public String createToken(String userId, List<String> auth) {
        Claims claims = Jwts.claims().setSubject(userId); // JWT Payload에 저장되는 정보단위
        claims.put("auth", auth); // 정보는 key-value 형식으로 저장
        Date date = new Date();
        return Jwts.builder()
                .setClaims(claims) // 정보 저장
                .setIssuedAt(date) // 토큰 발생 시간
                .setExpiration(new Date(date.getTime() + tokenValidTime))// 토큰 유효시간 설정
                .signWith(SignatureAlgorithm.HS256, secretKey) // 암호화 알고리즘, secreat 값
                .compact();
    }

    /**
     * 인증정보 조회
     *
     * @param token String token
     * @return Authentication UsernamePasswordAuthenticationToken
     */
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.findUser(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
     * 토큰을 통한 회원정보 조회
     *
     * @param token String token
     * @return String userId
     */
    public String findUser(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey(secretKey))
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * 토큰 유효성, 만료일자 검증
     *
     * @param jwtToken String jwtToken
     * @return boolean true, false
     */
    public boolean validationToken(String jwtToken) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(getSecretKey(secretKey))
                    .build()
                    .parseClaimsJws(jwtToken);
            return !claimsJws.getBody().getExpiration().before(new Date());
        } catch (Exception exception) {
            return false;
        }
    }

    /**
     * Request의 Header에서 token 값 가져오기
     *
     * @param request HttpServletRequest
     * @return String token
     */
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}

package com.spring.jwt.token;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * Jwt Token 생성, 인증, 권한부여, 유효성검사 , pk 추출 등의 기능을 제공하는 클래스
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final UserDetailsService userDetailsService;

    @Value("${jwt.secret}")
    private String secretKey;
    @Value("${jwt.accessTokenValidTime}")
    private Long accessTokenValidTime ;
    @Value("${jwt.refreshTokenValidTime}")
    private Long refreshTokenValidTime;
    private final RedisService redisService;

    private Key getSecretKey(String secretKey) {
        byte[] KeyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(KeyBytes);
    }

    /**
     * AccessToken과 RefreshToken을 동시에 생성하여 TokenDTO 반환
     *
     * @param authentication authentication
     * @return TokenDTO grantType, accessToken, refreshToken
     */
    public TokenDTO generateToken(Authentication authentication) {

        String authorities = getAuthorities(authentication);
        Date accessTokenExpiresIn = setTokenExpiresIn(accessTokenValidTime);
        Date refreshTokenExpiresIn = setTokenExpiresIn(refreshTokenValidTime);
        String accessToken = setAccessToken(authentication.getName(), authorities, accessTokenExpiresIn);
        String refreshToken = setRefreshToken(authentication.getName(), authorities,refreshTokenExpiresIn);

        redisService.setValues(authentication.getName(), refreshToken);

        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * AccessToken 설정
     *
     * @param userId               String userId
     * @param authorities          String authorities
     * @param accessTokenExpiresIn Date accessTokenTime
     * @return String accessToken
     */
    public String setAccessToken(String userId, String authorities, Date accessTokenExpiresIn) {

        Claims claims = Jwts.claims().setSubject(userId);
        claims.put("auth", authorities);

        return Jwts.builder()
                .setSubject(userId)
                .setClaims(claims) // 발행 유저 설정
                .setExpiration(accessTokenExpiresIn)// 토큰 유효시간 설정
                .signWith(getSecretKey(secretKey), SignatureAlgorithm.HS256) // 암호화 알고리즘, secreat 값
                .compact();
    }

    /**
     * RefreshToken 설정
     *
     * @param refreshTokenExpiresIn Date refreshTokenTime
     * @return String refreshToken
     */
    public String setRefreshToken(String userId, String authorities, Date refreshTokenExpiresIn) {
        Claims claims = Jwts.claims().setSubject(userId);
        claims.put("auth", authorities);

        return Jwts.builder()
                .setSubject(userId)
                .setClaims(claims) // 발행 유저 설정
                .setExpiration(refreshTokenExpiresIn)// 토큰 유효시간 설정
                .signWith(getSecretKey(secretKey), SignatureAlgorithm.HS256) // 암호화 알고리즘, secreat 값
                .compact();
    }

    /**
     * 토큰 만료 시간 설정
     *
     * @param tokenValidTime Long tokenValidTime
     * @return Date tokenValidTime
     */
    public Date setTokenExpiresIn(Long tokenValidTime) {
        long now = (new Date()).getTime();
        return new Date(now + tokenValidTime);
    }

    /**
     * 인증된 사용자 권한 가져오기
     * 
     * @param authentication Authentication 
     * @return String authorities
     */
    public String getAuthorities(Authentication authentication) {
        return authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }


    /**
     * 인증정보 조회
     *
     * @param accessToken String token
     * @return Authentication UsernamePasswordAuthenticationToken
     */
    public Authentication getAuthentication(String accessToken) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.findUser(accessToken));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
     * 토큰을 통한 회원정보 조회
     *
     * @param accessToken String token
     * @return String userId
     */
    public String findUser(String accessToken) {
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey(secretKey))
                .build()
                .parseClaimsJws(accessToken)
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
        } catch (ExpiredJwtException expiredJwtException) {
            log.info("ExpiredJwtException : {}", expiredJwtException.getMessage());
            return false;
        }
    }

    /**
     * JWT 토큰의 만료시간
     *
     * @param accessToken String accessToken
     * @return Long token Expiration
     */
    public Long getExpiration(String accessToken){
        Date expiration = Jwts.parserBuilder()
                .setSigningKey(getSecretKey(secretKey))
                .build()
                .parseClaimsJws(accessToken)
                .getBody()
                .getExpiration();
        long now = new Date().getTime();

        return expiration.getTime() - now;
    }

    /**
     * Request Header에서 accessToken 값 가져오기
     *
     * @param request HttpServletRequest
     * @return String token
     */
    public String resolveAccessToken(HttpServletRequest request) {

        String accessToken;
        String accessHeader = request.getHeader("Authorization");
        
        if (StringUtils.hasText(accessHeader) && accessHeader.startsWith("Bearer ")) {
            accessToken = accessHeader.substring(7);
            return accessToken;
        }

        return null;
    }

    /**
     * Request Header에서 refreshToken 값 가져오기
     * 
     * @param request HttpServletRequest
     * @return String refrehsToken
     */
    public String resolveRefreshToken(HttpServletRequest  request) {

        String refreshToken;
        String refreshHeader = request.getHeader("RefreshToken");

        if (StringUtils.hasText(refreshHeader) && refreshHeader.startsWith("Bearer ")) {
            refreshToken = refreshHeader.substring(7);
            return refreshToken;
        }
        
        return null;
    }

    /**
     * 재발급된 accessToken Header 설정
     *
     * @param response HttpServletResponse
     * @param newAccessToken String newAccessToken
     */
    public void setHeaderAccessToken(HttpServletResponse response, String newAccessToken) {
        response.setHeader("Authorization", "Bearer " + newAccessToken);
    }
}
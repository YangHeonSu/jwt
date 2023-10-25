package com.spring.jwt.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
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
import java.util.List;
import java.util.stream.Collectors;

/**
 * Jwt Token 생성, 인증, 권한부여, 유효성검사 , pk 추출 등의 기능을 제공하는 클래스
 */
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private long accessTokenValidTime = 30 * 60 * 1000L; // AccessToken 유효시간 30분
    private long refreshTokenValidTime = 60 * 60 * 100L; // RefreshToken 유효시간 30분
    private final UserDetailsService userDetailsService;

    @Value("${jwt.secret}")
    private String secretKey;

    private Key getSecretKey(String secretKey) {
        byte[] KeyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(KeyBytes);
    }

    /**
     * 토큰 생성1
     *
     * @param userId String userId
     * @param auth   List<String> auth
     * @return String token
     */
    public TokenDTO createToken(String userId, String auth) {
        long nowDate = (new Date()).getTime();
        Date accessTokenExpiresIn = new Date(nowDate + accessTokenValidTime);
        Date refreshTokenExpiresIn = new Date(nowDate + refreshTokenValidTime);

        // accessToken 생성
        String accessToken = Jwts.builder()
                .setSubject(userId) // 정보 저장
                .setExpiration(accessTokenExpiresIn)// 토큰 유효시간 설정
                .claim("auth", auth)
                .signWith(getSecretKey(secretKey), SignatureAlgorithm.HS256) // 암호화 알고리즘, secreat 값
                .compact();

        // refreshToken 생성
        String refreshToken = Jwts.builder()
                .setExpiration(refreshTokenExpiresIn)// 토큰 유효시간 설정
                .signWith(getSecretKey(secretKey), SignatureAlgorithm.HS256) // 암호화 알고리즘, secreat 값
                .compact();

        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken("Bearer " + accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * AccessToken과 RefreshToken을 동시에 생성하여 TokenDTO 반환
     *
     * @param authentication authentication
     * @return TokenDTO grantType, accessToken, refreshToken
     */
    public TokenDTO generateToken(Authentication authentication) {

        // 인증 객체에서 권한 정보 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long nowDate = (new Date()).getTime();
        Date accessTokenExpiresIn = new Date(nowDate + accessTokenValidTime);
        Date refreshTokenExpiresIn = new Date(nowDate + refreshTokenValidTime);

        // accessToken 생성
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName()) // 정보 저장
                .setExpiration(accessTokenExpiresIn)// 토큰 유효시간 설정
                .claim("auth", authorities)
                .signWith(getSecretKey(secretKey), SignatureAlgorithm.HS256) // 암호화 알고리즘, secreat 값
                .compact();

        // refreshToken 생성
        String refreshToken = Jwts.builder()
                .setExpiration(refreshTokenExpiresIn)// 토큰 유효시간 설정
                .signWith(getSecretKey(secretKey), SignatureAlgorithm.HS256) // 암호화 알고리즘, secreat 값
                .compact();

        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken("Bearer " + accessToken)
                .refreshToken(refreshToken)
                .build();

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

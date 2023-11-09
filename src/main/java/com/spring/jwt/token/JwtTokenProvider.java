package com.spring.jwt.token;

import com.spring.jwt.springsecurity.CustomUserDetail;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import java.util.stream.Collectors;

/**
 * Jwt Token 생성, 인증, 권한부여, 유효성검사 , pk 추출 등의 기능을 제공하는 클래스
 */
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    //private final long accessTokenValidTime = 30 * 60 * 1000L; // AccessToken 유효시간 30분
    //private final long refreshTokenValidTime = 60 * 60 * 100L; // RefreshToken 유효시간 30분
    private final UserDetailsService userDetailsService;

    @Value("${jwt.secret}")
    private String secretKey;
    @Value(("${jwt.access-token-time}"))
    private Long accessTokenValidTime;
    @Value(("${jwt.refresh-token-time}"))
    private Long refreshTokenValidTime;

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
        Date refreshTokenExpiresIn = setTokenExpiresIn( refreshTokenValidTime);
        String accessToken = setAccessToken(authentication.getName(), authorities, accessTokenExpiresIn);
        String refreshToken = setRefreshToken(refreshTokenExpiresIn);


        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken("Bearer " + accessToken)
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
        return Jwts.builder()
                .setSubject(userId) // 정보 저장
                .setExpiration(accessTokenExpiresIn)// 토큰 유효시간 설정
                .claim("auth", authorities)
                .signWith(getSecretKey(secretKey), SignatureAlgorithm.HS256) // 암호화 알고리즘, secreat 값
                .compact();
    }

    /**
     * RefreshToken 설정
     *
     * @param refreshTokenExpiresIn Date refreshTokenTime
     * @return String refreshToken
     */
    public String setRefreshToken(Date refreshTokenExpiresIn) {
        return Jwts.builder()
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
    public boolean validationToken(String jwtToken, HttpServletResponse response) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(getSecretKey(secretKey))
                    .build()
                    .parseClaimsJws(jwtToken);

            if (isAccessTokenExpired(jwtToken)) { // accessToken이 만료된 경우
                // refreshToken을 통해 accessToken 재발급 로직
                String refreshToken = getRefreshToken(jwtToken);
                TokenDTO accessToken = newAccessToken(refreshToken); // 새로 발급된 AccessToken

                response.setHeader("Authorization", "Bearer " + accessToken.getAccessToken());
                return true;
            } else {
                return false;
            }

        } catch (Exception exception) {
            return false;
        }
    }


    /**
     * RefreshToken을 통해 accessToken 재발급
     *
     * param refreshToken
     * @return
     */
    public TokenDTO newAccessToken(String refreshToken) {

        String userId = getUsername(refreshToken);
        CustomUserDetail userDetails = (CustomUserDetail) userDetailsService.loadUserByUsername(userId);
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        // 인증 객체에서 권한 정보 가져오기
        String authorities = getAuthorities(authentication);

        long nowDate = (new Date()).getTime();
        Date accessTokenExpiresIn = new Date(nowDate + accessTokenValidTime);

        // accessToken 생성
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName()) // 정보 저장
                .setExpiration(accessTokenExpiresIn)// 토큰 유효시간 설정
                .claim("auth", authorities)
                .signWith(getSecretKey(secretKey), SignatureAlgorithm.HS256) // 암호화 알고리즘, secreat 값
                .compact();
        return TokenDTO.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .build();
    }

    /**
     * 토큰에서 사용자 아이디 조회
     *
     * @param refreshToken String token
     * @return String userId
     */
    private String getUsername(String refreshToken) {
        Claims claims = extractClaims(refreshToken);
        return claims.getSubject();
    }

    /**
     * Claims 정보에서 refreshToken 정보 가져오기
     *
     * @param jwtToken String jwtToken
     * @return String refreshToken
     */
    private String getRefreshToken(String jwtToken) {
        Claims claims = extractClaims(jwtToken);
        return claims.get("refreshToken", String.class);
    }

    /**
     * AccessToken 만료 여부 확인
     *
     * @param jwtToken String jwtToken
     * @return boolean true false (true -> 만료, false-> 유효)
     */
    private boolean isAccessTokenExpired(String jwtToken) {
        Claims claims = extractClaims(jwtToken);
        Date expiration = claims.getExpiration(); // accessToken 만료일자 추출
        return expiration != null && expiration.before(new Date()); // 만료 일자가 null이 아니고 현재 시간이전일 경우 true
    }


    /**
     * 토큰에서 Claims 정보 추출
     *
     * @param jwtToken String jwtToken
     * @return Claims
     */
    private Claims extractClaims(String jwtToken) {
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey(secretKey))
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }

    /**
     * Request Header에서 accessToken 값 가져오기
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

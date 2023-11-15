package com.spring.jwt.token;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Jwt가 유효한 토큰인지 인증하기 위한 Filter.
@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request
            , HttpServletResponse response
            , FilterChain filterChain) throws ServletException, IOException {

        String accessToken = jwtTokenProvider.resolveAccessToken(request);
        String refreshToken = jwtTokenProvider.resolveRefreshToken(request);

        log.info("accessToken : {}", accessToken);
        log.info("refreshToken : {}", refreshToken);

        if (accessToken != null) {
            // accessToken이 유효한 경우
            if (jwtTokenProvider.validationToken(accessToken)) {
                this.setAuthentication(accessToken);
                filterChain.doFilter(request, response);
            } else if (!jwtTokenProvider.validationToken(accessToken) && refreshToken == null) { // accessToken이 만료되어 refreshToken을 통해 accessToken을 재발급 요청을 위한 response 설정

            } else if (!jwtTokenProvider.validationToken(accessToken) && jwtTokenProvider.validationToken(refreshToken)) {

                // refreshToen으로 Authentication 조회
                Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken);
                TokenDTO tokenDTO = jwtTokenProvider.generateToken(authentication);

                log.info("new accessToken : {}", tokenDTO.getAccessToken());

                jwtTokenProvider.setHeaderAccessToken(response, tokenDTO.getAccessToken());
                this.setAuthentication(tokenDTO.getAccessToken());
                filterChain.doFilter(request, response);
            } else {
                // 로그아웃 처리
                log.info("accessToken, refreshToken 모두 만료");
            }
        } else { // accessToken이 null일 경우
            filterChain.doFilter(request, response);
        }
    }

    /**
     * accessToken으로 Authentication 설정
     * 
     * @param accessToken String accessToken
     */
    public void setAuthentication(String accessToken) {
        //accessToken에서 Authentication 객체를 가지고 와서 SecurityContext에 저장
        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
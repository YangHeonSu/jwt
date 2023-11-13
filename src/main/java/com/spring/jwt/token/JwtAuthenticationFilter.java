package com.spring.jwt.token;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Jwt가 유효한 토큰인지 인증하기 위한 Filter.
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request
            , HttpServletResponse response
            , FilterChain filterChain) throws ServletException, IOException {

        // Header Token 가져오기
        String accessToken = jwtTokenProvider.resolveToken(request);

        if (accessToken != null) {
            // accessToken이 유효한 경우
            if (jwtTokenProvider.validationToken(accessToken)) {
                this.setAuthentication(accessToken);
            } else if (!jwtTokenProvider.validationToken(accessToken))  { // accessToken이 유효하지 않지만 refreshToken은 유효한 경우

            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     *
     * @param accessToken String accessToken
     */
    public void setAuthentication(String accessToken) {
        //accessToken에서 Authentication 객체를 가지고 와서 SecurityContext에 저장
        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
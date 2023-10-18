package com.spring.jwt.springsecurity;

import com.spring.jwt.token.JwtTokenProvider;
import com.spring.jwt.token.TokenDTO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request
            , HttpServletResponse response
            , Authentication authentication) throws IOException, ServletException {


        SecurityContextHolder.getContext().setAuthentication(authentication);
        TokenDTO tokenDTO = jwtTokenProvider.generateToken(authentication); // 인증 개체를 통한 Token 생성

        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokenDTO.getRefreshToken())
                .maxAge(7*2*60*60) // 토큰(RefreshToken)의 유효 시간
                .path("/") // ??
                .secure(true) // Https 환경에서만 쿠키가 발동
                .sameSite("None") // 동일 사이트와 크로스 사이트에 모두 쿠키 전송이 가능
                .httpOnly(true) // 브라우저에서 쿠키에 접근할 수 없도록 설정
                .build();


        // 로그인 (아이디 및 비밀번호) 검증이 성공되었을 때 실행되는 메서드
        // Token 발급 하는 프로세스 구현
        response.setContentType("application/json");
        response.setHeader("Set-Cookie", cookie.toString());

        log.info("Login Success");

    }
}

package com.spring.jwt.login;

import com.spring.jwt.token.JwtTokenProvider;
import com.spring.jwt.token.TokenDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final LoginService loginService;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 로그인 요청
     *
     * @param loginDTO String userId, String password
     * @return TokenDTO
     */
    @PostMapping("/api/login")
    public ResponseEntity<TokenDTO> login(@RequestBody LoginDTO loginDTO) {
        TokenDTO tokenDTO = loginService.login(loginDTO);
        return ResponseEntity.ok(tokenDTO);
    }

    /**
     * 로그인 성공 시 토큰 정보 반환
     *
     * @param request HttpServletRequest request
     * @param response HttpServletResponse response
     * @return ResponseEntity<Token> 토큰 정보
     */
    @PostMapping("/api/login/success")
    public ResponseEntity<TokenDTO> getLoginSuccessInfo(HttpServletRequest request, HttpServletResponse response) {
        // Token 발급 하는 프로세스 구현
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // 인증 객체 가져오기
        TokenDTO tokenDTO = jwtTokenProvider.generateToken(authentication); // 인증 개체를 통한 Token 생성

        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokenDTO.getRefreshToken())
                .maxAge(60 * 60 * 100L) // 토큰(RefreshToken)의 유효 시간
                .path("/") // ??
                .secure(true) // Https 환경에서만 쿠키가 발동
                .sameSite("None") // 동일 사이트와 크로스 사이트에 모두 쿠키 전송이 가능
                .httpOnly(true) // 브라우저에서 쿠키에 접근할 수 없도록 설정
                .build();

        response.setContentType("application/json");
        response.setHeader("Set-Cookie", cookie.toString());
        
        // 현재는 RefreshToken, AccessToken, grantType 모두 반환되지만 추후 로그인 인증 객체와 AccessToken만 반환되도록 변경 예정
        return ResponseEntity.ok(tokenDTO);
    }

    /**
     * 로그인 실패 메세지
     * @return ResponseEntity<Map<String, Object>> LoginFailMessage
     */
    @PostMapping("/api/login/fail")
    public ResponseEntity<Map<String, Object>> getLoginFailInfo() {
        Map<String, Object> failInfo = new HashMap<>();

        failInfo.put("message", "loginFail");
        return ResponseEntity.ok(failInfo);
    }
}

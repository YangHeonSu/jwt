package com.spring.jwt.login;

import com.spring.jwt.token.TokenDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final LoginService loginService;

    /**
     * 로그인 요청
     * @param loginDTO String userId, String password
     * @return TokenDTO
     */
    @PostMapping("/api/login")
    public ResponseEntity<TokenDTO> login(@RequestBody LoginDTO loginDTO) {
        TokenDTO tokenDTO = loginService.login(loginDTO);
        return ResponseEntity.ok(tokenDTO);
    }
}

package com.spring.jwt.login;

import com.spring.jwt.springsecurity.CustomUserDetail;
import com.spring.jwt.token.JwtTokenProvider;
import com.spring.jwt.token.TokenDTO;
import com.spring.jwt.user.User;
import com.spring.jwt.user.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class LoginService {

    private final JwtTokenProvider jwtTokenProvider;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;

    /**
     * 로그인
     *
     * @param loginDTO String userId, String password
     * @param httpServletResponse HttpServletResponse
     * @return LoginResponseDTO loginResult
     */
    public LoginResponseDTO login(LoginRequestDTO loginDTO
            , HttpServletResponse httpServletResponse) {

        LoginResponseDTO loginResponseDTO = new LoginResponseDTO();
        Map<String, Object> loginRequestValidMessage = loginRequestValidation(loginDTO);

        if (loginRequestValidMessage.isEmpty()) {

            CustomUserDetail customUserDetail = (CustomUserDetail) userDetailsService.loadUserByUsername(loginDTO.getUserId());
            Authentication authentication = new UsernamePasswordAuthenticationToken(customUserDetail, null, customUserDetail.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            TokenDTO token = jwtTokenProvider.generateToken(authentication);
            // 4. 인증 객체를 설정한다.

            loginResponseDTO.setTokenDTO(token);
            loginResponseDTO.setAuth(authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(",")));
            loginResponseDTO.setName(authentication.getName());
            loginResponseDTO.setUserId(authentication.getName());

            setRefreshTokenCookie(loginResponseDTO, httpServletResponse);
        } else {
            loginResponseDTO.setMessage(loginRequestValidMessage);
        }

        return loginResponseDTO;
    }

    /**
     * Cookie에 RefreshToken 설정
     *
     * @param loginResponseDTO String refreshToken
     * @param httpServletResponse HttpServletResponse
     */
    public void setRefreshTokenCookie(LoginResponseDTO loginResponseDTO
            , HttpServletResponse httpServletResponse) {
        ResponseCookie cookie = ResponseCookie.from("refreshToken", loginResponseDTO.getTokenDTO().getRefreshToken())
                .maxAge(60 * 60 * 100L) // 토큰(RefreshToken)의 유효 시간
                .path("/") // ??
                .secure(true) // Https 환경에서만 쿠키가 발동
                .sameSite("None") // 동일 사이트와 크로스 사이트에 모두 쿠키 전송이 가능
                .httpOnly(true) // 브라우저에서 쿠키에 접근할 수 없도록 설정
                .build();

        httpServletResponse.setContentType("application/json");
        httpServletResponse.setHeader("Set-Cookie", cookie.toString());
    }

    /**
     * 아이디 및 비밀번호 검증
     *
     * @param loginRequestDTO String userId, String password
     * @return Map<String,Object> loginValidResult
     */
    public Map<String, Object> loginRequestValidation(LoginRequestDTO loginRequestDTO) {

        Map<String, Object> loginResult = new HashMap<>();
        
        // 아이디가 존재하지 않을 경우
        if (!userRepository.existsByUserId(loginRequestDTO.getUserId())) {
            loginResult.put("message", "아이디가 존재하지 않습니다.");
            return loginResult;
        }
        
        // 아이디가 존재하는 경우
        CustomUserDetail customUserDetail = (CustomUserDetail) userDetailsService.loadUserByUsername(loginRequestDTO.getUserId());

        // 비밀번호가 일치하지 않는 경우
        if (!bCryptPasswordEncoder.matches(loginRequestDTO.getPassword(), customUserDetail.getPassword())) {
            loginResult.put("message", "비밀번호가 일치하지 않습니다.");
            return loginResult;
        }

        return loginResult;
    }

    /*        // Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이 시점에서 Authentication은 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(loginDTO.getUserId(), loginDTO.getPassword());
        // 실제 검증( 아이디 및 비밀번호)가 이루어지는 부분
        // authenticate 가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 이 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        log.info("authentication : {}", authentication);
        // 인증 정보를 기반으로 jwt 토큰 생성
        return jwtTokenProvider.generateToken(authentication);*/
}

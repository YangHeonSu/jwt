package com.spring.jwt.login;

import com.spring.jwt.springsecurity.CustomUserDetail;
import com.spring.jwt.token.JwtTokenProvider;
import com.spring.jwt.token.TokenDTO;
import com.spring.jwt.user.User;
import com.spring.jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
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

    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;


    @Transactional
    public LoginResponseDTO loginResponse(LoginDTO loginDTO) {

        Optional<User> user = userRepository.findByUserId(loginDTO.getUserId());
        CustomUserDetail customUserDetail = (CustomUserDetail) userDetailsService.loadUserByUsername(loginDTO.getUserId());

        Map<String, Object> loginRequestValidMessage = loginRequestValidation(loginDTO, user);
        LoginResponseDTO loginResponseDTO = new LoginResponseDTO();
        if (loginRequestValidMessage.isEmpty()) {
            TokenDTO token = jwtTokenProvider.createToken(user.get().getUserId(), user.get().getAuth());
            // 4. 인증 객체를 설정한다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(customUserDetail, null, customUserDetail.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            loginResponseDTO.setTokenDTO(token);
            loginResponseDTO.setAuth(authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(",")));
            loginResponseDTO.setName(authentication.getName());
            loginResponseDTO.setUserId(authentication.getName());
        } else {
            log.info("login Fail");
        }

        return loginResponseDTO;
    }

    public Map<String, Object> loginRequestValidation(LoginDTO loginDTO, Optional<User> user) {

        Map<String, Object> loginResult = new HashMap<>();
        // 아이디 및 비밀번호 검증
        // 아이디가 존재할 경우
        if (user.isPresent()) {
            if (!bCryptPasswordEncoder.matches(loginDTO.getPassword(), user.get().getPassword())) {
                loginResult.put("message", "아이디가 존재하지 않습니다.");
            }
        } else { // 아이디가 존재하지 않을 경우
            loginResult.put("message", "비밀번호가 일치하지 않습니다.");
        }

        return loginResult;
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
}

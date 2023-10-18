package com.spring.jwt.login;

import com.spring.jwt.token.JwtTokenProvider;
import com.spring.jwt.token.TokenDTO;
import com.spring.jwt.user.User;
import com.spring.jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class LoginService {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    @Transactional
    public TokenDTO login(LoginDTO loginDTO) {

/*        Optional<User> user = Optional.ofNullable(userRepository.findByUserId(loginDTO.getUserId())
                .orElseThrow(() -> new UsernameNotFoundException("UserId Not Exists")));

        if (!bCryptPasswordEncoder.matches(loginDTO.getPassword(), user.get().getPassword())) {
            log.info("message : {}", "Password is wrong");
            throw new BadCredentialsException("Password is wrong");
        }

        return jwtTokenProvider.generateToken(user.get().getUserId(), user.get().getAuth());*/

        // Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이 시점에서 Authentication은 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(loginDTO.getUserId(), loginDTO.getPassword());
        // 실제 검증( 아이디 및 비밀번호)가 이루어지는 부분
        // authenticate 가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 이 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        log.info("authentication : {}", authentication);
        // 인증 정보를 기반으로 jwt 토큰 생성
        return jwtTokenProvider.generateToken(authentication);
    }
}

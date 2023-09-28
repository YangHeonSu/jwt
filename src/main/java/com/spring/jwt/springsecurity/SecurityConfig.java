package com.spring.jwt.springsecurity;

import com.spring.jwt.token.JwtAuthenticationFilter;
import com.spring.jwt.token.JwtTokenProvider;
import jakarta.servlet.DispatcherType;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@EnableWebSecurity  //Spring Security 설정 활성화
@Configuration
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.csrf(AbstractHttpConfigurer::disable) // token 방식을 사용하기 때문에 csrf 비활성화
                .httpBasic(AbstractHttpConfigurer::disable) // JWT 방식을 사용함으로(Bearer 방식) 비활성화
                .formLogin(AbstractHttpConfigurer::disable) // 로그인 폼 비활성화 ( SpringSecurity 로그인 폼을 사용안함)
                .sessionManagement(sessionManagement
                        -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // 세션 사용 x

        // JWT 인증을 위하여 직접 구현한 필터를 UsernamePasswordAuthenticationFilter 전에 실행하겠다는 설정.
        httpSecurity.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider)
                , UsernamePasswordAuthenticationFilter.class);

        // API에 대한 권한 체크
        httpSecurity.authorizeHttpRequests(authorizationManager -> authorizationManager
                .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                .anyRequest().permitAll());

        return httpSecurity.build();
    }

    @Bean
    public BCryptPasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }
}

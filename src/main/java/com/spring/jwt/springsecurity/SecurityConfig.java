package com.spring.jwt.springsecurity;

import com.spring.jwt.token.JwtAuthenticationFilter;
import com.spring.jwt.token.JwtTokenProvider;
import com.spring.jwt.token.RedisService;
import jakarta.servlet.DispatcherType;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
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
    private final RedisService redisService;

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.csrf(AbstractHttpConfigurer::disable) // token 방식을 사용하기 때문에 csrf 비활성화
                .httpBasic(AbstractHttpConfigurer::disable) // JWT 방식을 사용함으로(Bearer 방식) 비활성화
                .formLogin(AbstractHttpConfigurer::disable) // 로그인 폼 비활성화 ( SpringSecurity 로그인 폼을 사용안함)
                .sessionManagement(sessionManagement
                        -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // 세션 사용 x
        // eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWRnanN0biIsImF1dGgiOiJST0xFX0FETUlOIiwiZXhwIjoxNzAwMDU0NjA3fQ.SBtc_ctqoZ_0G2TdSuieQjEjFIsWvgFl_V9u9xpHUGE

        // eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWRnanN0biIsImF1dGgiOiJST0xFX0FETUlOIiwiZXhwIjoxNzAwMDUyODY3fQ.IXNJ7kyQVIizCqKwhXn-tB1WdFgXUHfAcy-jCJjaOxM

        // eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWRnanN0biIsImF1dGgiOiJST0xFX0FETUlOIiwiZXhwIjoxNzAwMDU0ODAxfQ.8QV2PdhDdoaoXRZ4SwAE_b8DmMxEEzwZ8UXJq3gwHM8

        // JWT 인증을 위하여 직접 구현한 필터를 UsernamePasswordAuthenticationFilter 전에 실행하겠다는 설정.
        httpSecurity.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, redisService)
                , UsernamePasswordAuthenticationFilter.class);

        // API에 대한 권한 체크
        httpSecurity.authorizeHttpRequests(authorizationManager -> authorizationManager
                .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                .requestMatchers("/api/users").authenticated()
                .anyRequest().permitAll());

        return httpSecurity.build();
    }

    @Bean
    public BCryptPasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}

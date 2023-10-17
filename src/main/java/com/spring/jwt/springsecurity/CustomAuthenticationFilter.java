package com.spring.jwt.springsecurity;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import java.io.IOException;

// UsernamePasswordAuthenticationFilter -> Spring Security에서 formLogin formData 을 할 때 사용할 수 있는 Filter.
@Slf4j
@Component
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    public CustomAuthenticationFilter(UserDetailsService userDetailsService
            , BCryptPasswordEncoder bCryptPasswordEncoder
            , AuthenticationManager authenticationManager
            , CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler
            , CustomAuthenticationFailureHandler customAuthenticationFailureHandler) {

        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.customAuthenticationSuccessHandler = customAuthenticationSuccessHandler;
        this.customAuthenticationFailureHandler = customAuthenticationFailureHandler;
        super.setAuthenticationManager(authenticationManager);
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login2", HttpMethod.POST.name()));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String userId = request.getParameter("userId"); // 로그인 아이디
        String password = request.getParameter("password"); // 로그인 비밀번호

        CustomUserDetail customUserDetail = (CustomUserDetail) userDetailsService.loadUserByUsername(userId);

        if (customUserDetail.getUsername() == null) {
            throw new UsernameNotFoundException("UserId is Empty");
        }
        if (!bCryptPasswordEncoder.matches(password, customUserDetail.getPassword())) {
            throw new BadCredentialsException("비밀번호 틀림");
        }

        return new UsernamePasswordAuthenticationToken(customUserDetail, null, customUserDetail.getAuthorities());

/*        ObjectMapper objectMapper = new ObjectMapper();
        LoginDTO loginDTO = new LoginDTO();
        try {
             loginDTO = objectMapper.readValue(request.getInputStream(), LoginDTO.class);
        }catch (Exception e) {
            e.printStackTrace();
        }
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDTO.getUserId(), loginDTO.getPassword());

        return authenticationManager.authenticate(authenticationToken);*/
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request
            , HttpServletResponse response
            , FilterChain filterChain
            , Authentication authentication) throws ServletException, IOException {
        customAuthenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request
            , HttpServletResponse response
            , AuthenticationException authenticationException) throws ServletException, IOException {
        customAuthenticationFailureHandler.onAuthenticationFailure(request,response, authenticationException);
    }
}

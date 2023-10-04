package com.spring.jwt.springsecurity;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.jwt.login.LoginDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// UsernamePasswordAuthenticationFilter -> Spring Security에서 formLogin을 할 때 사용할 수 있는 Filter.
@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String userId = request.getParameter("userId"); // 로그인 아이디
        String password = request.getParameter("password"); // 로그인 비밀번호

        CustomUserDetail customUserDetail = (CustomUserDetail) userDetailsService.loadUserByUsername(userId);

        if (customUserDetail.getUsername() == null) {
            throw new UsernameNotFoundException("UserId is Empty");
        }
        if (!bCryptPasswordEncoder.matches(customUserDetail.getPassword(), password)) {
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
}

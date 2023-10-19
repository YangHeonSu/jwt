package com.spring.jwt.springsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request
            , HttpServletResponse response
            , AuthenticationException exception) throws IOException, ServletException {

        if (exception instanceof UsernameNotFoundException) {
            log.info("LoginFail Reason : {}", "User Not Exists");
            log.info("LoginFail Reason : {}", exception.getMessage());
        } else if (exception instanceof BadCredentialsException) {
            log.info("LoginFail Reason : {}", "Password is Wrong");
            log.info("LoginFail Reason : {}", exception.getMessage());
        }

        request.getRequestDispatcher("/api/login/fail").forward(request,response);
    }
}

package com.spring.jwt.token;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Jwt가 유효한 토큰인지 인증하기 위한 Filter.
@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;

    @Override
    protected void doFilterInternal(HttpServletRequest request
            , HttpServletResponse response
            , FilterChain filterChain) throws ServletException, IOException {

        String accessToken = jwtTokenProvider.resolveAccessToken(request);
        String refreshToken = jwtTokenProvider.resolveRefreshToken(request);

        if (accessToken != null) {  // accessToken이 존재하는 경우
            if (validBlackToken(accessToken)) { // 로그아웃된 accessToken이 아닌 경우
                log.info("로그아웃된 accessToken이 아님");
                if (jwtTokenProvider.validationToken(accessToken)) { // accessToken이 유효한 경우
                    log.info("access 유효");
                    this.setAuthentication(accessToken);
                    filterChain.doFilter(request, response);

                }  else if (!jwtTokenProvider.validationToken(accessToken)) { // accessToken이 만료되었을 때 refreshToken으로 accessToken을 재발급하기 위해 response 설정 하기 위함
                    if (refreshToken == null) {
                        log.info("access 만료");
                        getAccessTokenExpiredResult(response);
                    } else if (jwtTokenProvider.validationToken(refreshToken)){
                        Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken); // refreshToken으로 Authentication 정보 가져오기
                        String redisRefreshToken = redisService.getValues(authentication.getName()); // Redis에 저장된 refreshToken 가져오기

                        if (redisRefreshToken.equals(refreshToken)) { // 요청 들어온 refreshToken 정보와 redis에 저장된 refreshToken이 일치하는 경우
                            // Authentication으로 accessToken 재발급
                            TokenDTO reAccessToken = jwtTokenProvider.generateToken(authentication);
                            jwtTokenProvider.setHeaderAccessToken(response, reAccessToken.getAccessToken());

                            this.setAuthentication(reAccessToken.getAccessToken());
                            filterChain.doFilter(request, response);
                            log.info("요청 refreshToken과 redis에 저장된 refreshToken이 일치");

                        } else { // 요청 들어온 refreshToken 정보와 redis에 저장된 refreshToken이 일치하지 않는 경우
                            redisService.deleteValues(authentication.getName()); //
                            getTokenExpiredResult(response);
                            log.info("요청 refreshToken과 redis에 저장된 refreshToken이 일치하지 않음.");
                        }
                    } else { //accessToken, refreshToken 모두 만료된 경우
                        getTokenExpiredResult(response);
                        log.info("accessToken, refreshToken 모두 만료");
                    }
                }
            } else { // 로그아웃된 accessToken인 경우
                getTokenExpiredResult(response);
                SecurityContextHolder.clearContext();
                log.info("Logout Token");
            }
        } else { // acceeToken이 존재하지 않는 경우
            filterChain.doFilter(request, response);
        }
    }

    /**
     * accessToken으로 Authentication 설정
     * 
     * @param accessToken String accessToken
     */
    public void setAuthentication(String accessToken) {
        //accessToken에서 Authentication 객체를 가지고 와서 SecurityContext에 저장
        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /**
     * accessToken이 만료되었을 때 response 설정
     * 
     * @param response HttpServletResponse status, contentType
     */
    public void getAccessTokenExpiredResult(HttpServletResponse response) {
        try {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"message\" : \"401\"}");
        } catch (IOException ioException) {
            log.info("IOException : {}" , ioException.getMessage());
        }
    }

    /**
     * accessToken, refreshToken 모두 만료되었을 때 or 로그아웃된 accessToken으로 api 요청 시 response 설정
     * response 201 설정 -> 로그아웃 처리 -> 로그인 페이지 이동
     *
     * @param response HttpServletResponse status, contentType
     */
    public void getTokenExpiredResult(HttpServletResponse response) {
        try {
            response.setStatus(HttpServletResponse.SC_CREATED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"message\" : \"201\"}");
        } catch (IOException ioException) {
            log.info("IOException : {}" , ioException.getMessage());
        }
    }

    /**
     * api 요청 시 로그아웃된 accessToken인지 검증
     * 
     * @param accessToken String accessToken
     * @return Boolean true, false
     */
    public boolean validBlackToken(String accessToken) {

        boolean isBlackToken = true;
        //Redis에 있는 엑세스 토큰인 경우 로그아웃 처리된 엑세스 토큰임.
        String blackToken = redisService.getValues(accessToken);
        if(blackToken != null) {
            isBlackToken = false;
        }
        return isBlackToken;
    }
}
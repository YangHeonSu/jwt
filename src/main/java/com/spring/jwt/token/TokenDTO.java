package com.spring.jwt.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@AllArgsConstructor
@Data
public class TokenDTO {
    private String grantType;
    private String accessToken;
    private String refreshToken;
}

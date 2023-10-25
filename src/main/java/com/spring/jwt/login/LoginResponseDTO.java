package com.spring.jwt.login;

import com.spring.jwt.token.TokenDTO;
import lombok.Data;

@Data
public class LoginResponseDTO {

    private String userId;
    private String name;
    private String auth;
    private TokenDTO tokenDTO;
}

package com.spring.jwt.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDTO {

    private int id;
    private String userId;
    private String password;
    private String name;
    private String auth;

    // DTO 가 Entity 에 의존하는 것은 문제가 되지 않는다.
    public UserDTO(User user) {
        this.userId = user.getUserId();
        this.auth = user.getAuth();
        this.name = user.getName();
        this.password = user.getPassword();
        this.id = user.getId();
    }

    /**
     * 비밀번호 암호화 설정
     *
     * @param bCryptPasswordEncoder String password
     */
    public void bCryptPasswordEncoder(String bCryptPasswordEncoder) {
        this.password = bCryptPasswordEncoder;
    }

    // DTO -> Entity
    public User toEntity() {
        return User.builder()
                .userId(userId)
                .password(password)
                .name(name)
                .auth(auth)
                .build();
    }
}

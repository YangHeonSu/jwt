package com.spring.jwt.user;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * 계정 생성
     * @param userDTO UserDTO
     * @return Map<String, Object> saveResult
     */
    @PostMapping("/api/user")
    public Map<String, Object> save(@RequestBody UserDTO userDTO) {
        Map<String, Object> saveResult = new HashMap<>();
        userService.save(userDTO);

        saveResult.put("saveResult" ,200);
        return saveResult;
    }
}

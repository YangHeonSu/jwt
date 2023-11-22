package com.spring.jwt.user;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * 계정 생성
     *
     * @param userDTO UserDTO
     * @return Map<String, Object> saveResult
     */
    @PostMapping("/api/user")
    public Map<String, Object> save(@RequestBody UserDTO userDTO) {
        Map<String, Object> saveResult = new HashMap<>();
        userService.save(userDTO);

        saveResult.put("saveResult", 200);
        return saveResult;
    }


    /**
     * 계정 조회
     *
     * @return Map<String, Object> findAll Users
     */
    @GetMapping("/api/user")
    public Map<String, Object> findAll() {
        Map<String, Object> list = new HashMap<>();
        List<UserDTO> user = userService.findAll();

        list.put("data", user);

        return list;
    }
}

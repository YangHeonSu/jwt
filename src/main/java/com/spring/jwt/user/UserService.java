package com.spring.jwt.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * 계정 생성
     * @param userDTO UserDTO
     */
    public void save(UserDTO userDTO) {

        userDTO.bCryptPasswordEncoder(bCryptPasswordEncoder.encode(userDTO.getPassword()));

        User user = userDTO.toEntity();
        userRepository.save(user);
    }
}

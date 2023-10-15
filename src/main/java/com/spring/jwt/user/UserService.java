package com.spring.jwt.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * 계정 생성
     *
     * @param userDTO UserDTO
     */
    public void save(UserDTO userDTO) {

        userDTO.bCryptPasswordEncoder(bCryptPasswordEncoder.encode(userDTO.getPassword()));

        User user = userDTO.toEntity();
        userRepository.save(user);
    }

    /**
     * 계정 조회
     *
     * @return List<UserDTO> users
     */
    public List<UserDTO> findAll() {
        return userRepository.findAll()
                .stream()
                .map(UserDTO::new)
                .collect(Collectors.toList());
    }
}

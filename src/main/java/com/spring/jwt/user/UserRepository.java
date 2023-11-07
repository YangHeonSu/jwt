package com.spring.jwt.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    /**
     * 사용자 아이디를 통한 계정 조회
     *
     * @param userId String userId
     * @return Optional<User> user
     */
    Optional<User> findByUserId(String userId);

    /**
     * 사용자 아이디를 통해 계정 존재 유무 확인
     *
     * @param userId String userId;
     * @return boolean true, false
     */
    boolean existsByUserId(String userId);
}

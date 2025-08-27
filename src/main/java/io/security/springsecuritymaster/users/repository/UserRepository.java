package io.security.springsecuritymaster.users.repository;

import io.security.springsecuritymaster.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {

    // 유저이름으로 db에서 찾아오기
    Account findByUsername(String username);

}

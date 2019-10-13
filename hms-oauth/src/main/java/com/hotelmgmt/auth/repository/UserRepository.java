package com.hotelmgmt.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import com.hotelmgmt.auth.entity.User;

/**
 * The Interface UserRepository.
 * 
 * @author Gokulan
 */
@Repository
public interface UserRepository extends JpaRepository<User, String>, JpaSpecificationExecutor<User> {

    /**
     * Find by name.
     *
     * @param userName the user name
     * @return the user
     */
    User findByName(String userName);
}

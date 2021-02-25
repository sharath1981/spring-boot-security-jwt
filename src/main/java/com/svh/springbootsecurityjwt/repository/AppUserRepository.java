package com.svh.springbootsecurityjwt.repository;

import java.util.Optional;

import com.svh.springbootsecurityjwt.domain.AppUser;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    @EntityGraph(attributePaths = {"roles"})
    Optional<AppUser> findByUsername(String username);
}

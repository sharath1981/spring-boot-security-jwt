package com.svh.springbootsecurityjwt.service;

import java.util.Set;
import java.util.stream.Collectors;

import com.svh.springbootsecurityjwt.domain.AppUser;
import com.svh.springbootsecurityjwt.domain.Role;
import com.svh.springbootsecurityjwt.repository.AppUserRepository;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository appUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return appUserRepository.findByUsername(username)
                                .map(this::getUserDetails)
                                .orElseThrow(()->new UsernameNotFoundException(String.format("Username %s is not found...", username)));
    }

    private UserDetails getUserDetails(AppUser appUser) {
        return User.builder()
                   .username(appUser.getUsername())
                   .password(appUser.getPassword())
                   .accountExpired(!appUser.isAccountNonExpired())
                   .accountLocked(!appUser.isAccountNonLocked())
                   .credentialsExpired(!appUser.isCredentialsNonExpired())
                   .disabled(!appUser.isEnabled())
                   .authorities(getAuthorities(appUser))
                   .build();
    }

    private Set<SimpleGrantedAuthority> getAuthorities(AppUser appUser) {
        return appUser.getRoles().stream()
                                 .map(Role::getAuthority)
                                 .map(SimpleGrantedAuthority::new)
                                 .collect(Collectors.toSet());
    }
}

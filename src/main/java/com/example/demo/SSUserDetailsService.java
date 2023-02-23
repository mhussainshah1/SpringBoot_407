package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;
import java.util.*;

@Transactional
@Service
public class SSUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            User appUser = userRepository.findByUsername(username);
            if (appUser == null) {
                System.out.println("User not found with the provided username : " + appUser.toString());
                return null;
            }
            System.out.println("User from username : " + appUser);
            return new CustomerUserDetails(appUser, getAuthorities(appUser));
//            return new org.springframework.security.core.userdetails.User(
//                    appUser.getUsername(),
//                    appUser.getPassword(),
//                    getAuthorities(appUser));
        } catch (Exception e) {
            throw new UsernameNotFoundException("User not found");
        }
    }

    private String[] getRoles(User appUser) {
        List<String> roles = new ArrayList<>();
        for (Role role : appUser.getRoles()) {
            roles.add(role.getRole());
        }
        return Arrays.copyOf(roles.toArray(), roles.size(), String[].class);
    }

    private Set<GrantedAuthority> getAuthorities(User appUser) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        for (Role role : appUser.getRoles()) {
            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_" + role.getRole());
            authorities.add(grantedAuthority);
        }
        System.out.println("User authorities are : " + authorities.toString());
        return authorities;
    }
}

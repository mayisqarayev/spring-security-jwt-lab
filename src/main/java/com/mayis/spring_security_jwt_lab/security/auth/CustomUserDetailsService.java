package com.mayis.spring_security_jwt_lab.security.auth;

import com.mayis.spring_security_jwt_lab.entity.user.User;
import com.mayis.spring_security_jwt_lab.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = username.contains("@")
                ? userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User not found"))
                : userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new CustomUserDetails(user);
    }
}

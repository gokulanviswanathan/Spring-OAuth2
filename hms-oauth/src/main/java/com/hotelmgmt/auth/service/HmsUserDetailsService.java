package com.hotelmgmt.auth.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import com.hotelmgmt.auth.repository.UserRepository;
import com.hotelmgmt.auth.util.HmsUserAuthenticationProvider;

/**
 * The Class HmsUserDetailsService.
 * 
 * @author Gokulan
 */
@Service
public class HmsUserDetailsService implements UserDetailsService {

    /**
     * The hms user authentication provider.
     */
    @Autowired
    private HmsUserAuthenticationProvider hmsUserAuthenticationProvider;

    /**
     * The user repository.
     */
    @Autowired
    private UserRepository userRepository;

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.core.userdetails.UserDetailsService#
     * loadUserByUsername(java.lang.String)
     */
    @Override
    public UserDetails loadUserByUsername(final String userName) {
	final com.hotelmgmt.auth.entity.User user = userRepository.findByName(userName);
	final Set<SimpleGrantedAuthority> grantedAuthorities = new HashSet<>();
	grantedAuthorities.add(new SimpleGrantedAuthority(user.getPermission()));

	return new User(userName, user.getPassword(), true, true, true, true, grantedAuthorities);
    }

}

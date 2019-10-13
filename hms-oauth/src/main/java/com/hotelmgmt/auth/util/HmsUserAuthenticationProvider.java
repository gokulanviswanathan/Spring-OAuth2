package com.hotelmgmt.auth.util;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.hotelmgmt.auth.service.HmsUserDetailsService;

@Component
public class HmsUserAuthenticationProvider
	implements AuthenticationProvider, ApplicationListener<AbstractAuthenticationEvent> {

    /**
     * The password encoder.
     */
    @Autowired
    @Qualifier("passwordEncoder")
    private PasswordEncoder passwordEncoder;

    /**
     * The client information service.
     */
    @Autowired
    private HmsUserDetailsService hmsUserDetailsService;

    public HmsUserAuthenticationProvider() {
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.context.ApplicationListener#onApplicationEvent(org.
     * springframework.context.ApplicationEvent)
     */
    @Override
    public void onApplicationEvent(AbstractAuthenticationEvent arg0) {

    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.authentication.AuthenticationProvider#
     * authenticate(org.springframework.security.core.Authentication)
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	if (!supports(authentication.getClass())) {
	    throw new BadCredentialsException("Invalid credentials");
	}

	final String userName = authentication.getName();
	final String password = (String) authentication.getCredentials();

	final UserDetails user = hmsUserDetailsService.loadUserByUsername(userName);

	if (user == null) {
	    throw new BadCredentialsException("Invalid credentials");
	}

	if (!passwordEncoder.matches(password, user.getPassword())) {
	    throw new BadCredentialsException("Invalid credentials");
	}

	final Collection<? extends GrantedAuthority> authorities = user.getAuthorities();

	return new UsernamePasswordAuthenticationToken(user, password, authorities);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.springframework.security.authentication.AuthenticationProvider#supports(
     * java.lang.Class)
     */
    @Override
    public boolean supports(Class<?> authentication) {
	return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}

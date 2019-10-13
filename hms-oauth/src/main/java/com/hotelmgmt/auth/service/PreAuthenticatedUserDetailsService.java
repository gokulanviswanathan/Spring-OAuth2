package com.hotelmgmt.auth.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;

/**
 * The Class PreAuthenticatedUserDetailsService.
 * 
 * @author Gokulan
 */
@Service
public class PreAuthenticatedUserDetailsService
	implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    /** The token store. */
    private final TokenStore tokenStore;

    /**
     * Instantiates a new pre authenticated user details service.
     *
     * @param tokenStore the token store
     */
    public PreAuthenticatedUserDetailsService(final TokenStore tokenStore) {
	this.tokenStore = tokenStore;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.core.userdetails.
     * AuthenticationUserDetailsService#loadUserDetails(org.springframework.security
     * .core.Authentication)
     */
    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) {
	if (token.getPrincipal() instanceof UsernamePasswordAuthenticationToken) {
	    final UsernamePasswordAuthenticationToken userToken = (UsernamePasswordAuthenticationToken) token
		    .getPrincipal();

	    return (UserDetails) userToken.getPrincipal();
	}

	final OAuth2AccessToken accessToken = tokenStore.readAccessToken(token.getName());

	final OAuth2Authentication oauth = tokenStore.readAuthentication(accessToken);

	if (oauth == null || !oauth.isAuthenticated()) {
	    try {
		throw new Exception("Auth failed!");
	    } catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	    }
	}

	final UserDetails userDetails;

	final Set<SimpleGrantedAuthority> grantedAuthorities = new HashSet<>();
	grantedAuthorities.add(new SimpleGrantedAuthority("ALL_ACCESS"));

	if (oauth.isClientOnly()) {
	    userDetails = new User("hms-admin-client", "", grantedAuthorities);
	} else {
	    userDetails = (UserDetails) oauth.getPrincipal();
	}

	return userDetails;
    }
}

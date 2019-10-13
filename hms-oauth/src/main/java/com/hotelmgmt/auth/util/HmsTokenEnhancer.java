package com.hotelmgmt.auth.util;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import com.hotelmgmt.auth.repository.UserRepository;

/**
 * The Class HmsTokenEnhancer.
 * 
 * @author Gokulan
 */
public class HmsTokenEnhancer implements TokenEnhancer {

    @Autowired
    private UserRepository userRepository;

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.springframework.security.oauth2.provider.token.TokenEnhancer#enhance(org.
     * springframework.security.oauth2.common.OAuth2AccessToken,
     * org.springframework.security.oauth2.provider.OAuth2Authentication)
     */
    @Override
    public OAuth2AccessToken enhance(final OAuth2AccessToken accessToken, final OAuth2Authentication authentication) {
	final boolean isClientCredential = authentication.getAuthorities().stream()
		.anyMatch(match -> match.getAuthority().equalsIgnoreCase("ROLE_TRUSTED_CLIENT"));

	if (isClientCredential) {
	    return accessToken;
	}

	final User user = (User) authentication.getPrincipal();
	final String userName = user.getUsername();

	final com.hotelmgmt.auth.entity.User existingUser = userRepository.findByName(userName);

	final Map<String, Object> additionalInformation = new HashMap<>();
	additionalInformation.put("user", existingUser);

	((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInformation);

	return accessToken;
    }

}

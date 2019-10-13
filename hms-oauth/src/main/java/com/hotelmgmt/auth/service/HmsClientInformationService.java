package com.hotelmgmt.auth.service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.stereotype.Service;

import com.hotelmgmt.auth.util.HmsClientInformation;

/**
 * The Class HmsClientInformationService.
 * 
 * @author Gokulan
 */
@Service
public class HmsClientInformationService implements ClientDetailsService {

    /**
     * The password encoder.
     */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.oauth2.provider.ClientDetailsService#
     * loadClientByClientId(java.lang.String)
     */
    @Override
    public ClientDetails loadClientByClientId(final String clientId) {
	final ClientDetails clientDetails;

	if (clientId.equals("hms-admin")) {
	    clientDetails = generatePassword();
	} else if (clientId.equals("hms-admin-client")) {
	    clientDetails = generateClientCredentials();
	} else {
	    throw new ClientRegistrationException("Clients details not present!");
	}

	return clientDetails;
    }

    /**
     * Generate password.
     *
     * @return the client details
     */
    private ClientDetails generatePassword() {
	final HmsClientInformation clientInformation = new HmsClientInformation();
	try {
	    final Set<String> grantTypes = new HashSet();
	    grantTypes.add("password");
	    grantTypes.add("implicit");
	    grantTypes.add("refresh_token");

	    Set<String> scopes = new HashSet();
	    scopes.add("openid");

	    Set<String> resourceIds = new HashSet();
	    resourceIds.add("hms-auth-resource");

	    clientInformation.setClientId("hms-admin");
	    clientInformation.setClientSecret(passwordEncoder.encode("ACw1MbrDi"));
	    clientInformation.setAutoApprove(true);
	    clientInformation.setScope(scopes);
	    clientInformation.setAuthorities(Arrays.asList(() -> "ROLE_CLIENT"));
	    clientInformation.setAuthorizedGrantTypes(grantTypes);
	    clientInformation.setAccessTokenValiditySeconds(7200);
	    clientInformation.setResourceIds(resourceIds);

	} catch (Exception e) {
	    // TODO
	}

	return clientInformation;
    }

    /**
     * Generate client credentials.
     *
     * @return the client details
     */
    private ClientDetails generateClientCredentials() {
	final HmsClientInformation clientInformation = new HmsClientInformation();
	try {
	    final Set<String> grantTypes = new HashSet();
	    grantTypes.add("client_credentials");

	    Set<String> scopes = new HashSet();
	    scopes.add("openid");

	    Set<String> resourceIds = new HashSet();
	    resourceIds.add("hms-auth-resource");

	    clientInformation.setClientId("hms-admin-client");
	    clientInformation.setClientSecret(passwordEncoder.encode("ACw1MbrDi"));
	    clientInformation.setAutoApprove(true);
	    clientInformation.setScope(scopes);
	    clientInformation.setAuthorities(Arrays.asList(() -> "ROLE_TRUSTED_CLIENT"));
	    clientInformation.setAuthorizedGrantTypes(grantTypes);
	    clientInformation.setAccessTokenValiditySeconds(7200);
	    clientInformation.setResourceIds(resourceIds);

	} catch (Exception e) {
	    // TODO
	}

	return clientInformation;
    }
}

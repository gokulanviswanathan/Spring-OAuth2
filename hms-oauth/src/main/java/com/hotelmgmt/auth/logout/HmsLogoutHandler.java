package com.hotelmgmt.auth.logout;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

/**
 * The Class HmsLogoutHandler.
 * 
 * @author Gokulan
 */
public class HmsLogoutHandler extends SimpleUrlLogoutSuccessHandler implements LogoutSuccessHandler {

    /**
     * The token store.
     */
    @Autowired
    @Qualifier("tokenStore")
    private TokenStore tokenStore;

    /**
     * The session registry.
     */
    @Autowired
    @Qualifier("sessionRegistry")
    private SessionRegistry sessionRegistry;

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.web.authentication.logout.
     * SimpleUrlLogoutSuccessHandler#onLogoutSuccess(javax.servlet.http.
     * HttpServletRequest, javax.servlet.http.HttpServletResponse,
     * org.springframework.security.core.Authentication)
     */
    @Override
    public void onLogoutSuccess(final HttpServletRequest request, final HttpServletResponse response,
	    final Authentication authentication) throws IOException, ServletException {
	try {
	    if (request == null || request.getParameter("token") == null) {
		logoutAll();
	    } else {
		logoutByToken(request.getParameter("token"));
	    }
	} catch (Exception e) {

	}
    }

    /**
     * Logout all.
     */
    private void logoutAll() {
	final String clientId = "hms-admin";

	final Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientId(clientId);

	final List<OAuth2AccessToken> tokenValues = new ArrayList<>();
	tokenValues.addAll(tokens);

	for (OAuth2AccessToken accessToken : tokenValues) {
	    if (accessToken != null) {
		final OAuth2Authentication oauth = tokenStore.readAuthentication(accessToken);

		if (oauth != null) {
		    final List<SessionInformation> sessionInformation;
		    sessionInformation = sessionRegistry.getAllSessions(oauth.getPrincipal(), false);
		    sessionInformation.forEach(
			    sessionInfo -> sessionRegistry.removeSessionInformation(sessionInfo.getSessionId()));
		}

		tokenStore.removeAccessToken(accessToken);
		tokenStore.removeRefreshToken(accessToken.getRefreshToken());
	    }
	}
    }

    /**
     * Logout by token.
     *
     * @param tokenValue the token value
     */
    private void logoutByToken(final String tokenValue) {

	final OAuth2AccessToken accessToken = tokenStore.readAccessToken(tokenValue);
	final OAuth2Authentication oauth = tokenStore.readAuthentication(accessToken);

	if (oauth != null) {
	    final List<SessionInformation> sessionInformation;
	    sessionInformation = sessionRegistry.getAllSessions(oauth.getPrincipal(), false);
	    sessionInformation
		    .forEach(sessionInfo -> sessionRegistry.removeSessionInformation(sessionInfo.getSessionId()));
	}

	tokenStore.removeAccessToken(accessToken);
    }
}
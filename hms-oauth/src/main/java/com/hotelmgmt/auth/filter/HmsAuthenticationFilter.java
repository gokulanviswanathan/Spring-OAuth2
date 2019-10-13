package com.hotelmgmt.auth.filter;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.hotelmgmt.auth.logout.HmsLogoutHandler;

/**
 * The Class HmsAuthenticationFilter.
 * 
 * @author Gokulan
 */
public class HmsAuthenticationFilter extends OncePerRequestFilter {

    /**
     * The authentication manager.
     */
    private AuthenticationManager authenticationManager;

    /**
     * The authentication details source.
     */
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    /**
     * The remember me services.
     */
    private RememberMeServices rememberMeServices = new NullRememberMeServices();

    /**
     * The post only.
     */
    private boolean postOnly = true;

    /**
     * The ignore failure.
     */
    private boolean ignoreFailure = false;

    /**
     * The session registry.
     */
    @Autowired
    @Qualifier("sessionRegistry")
    private SessionRegistry sessionRegistry;

    /**
     * The hms logout handler.
     */
    @Autowired
    private HmsLogoutHandler hmsLogoutHandler;

    /**
     * Instantiates a new hms authentication filter.
     *
     * @param authenticationManager    the authentication manager
     * @param authenticationEntryPoint the authentication entry point
     */
    public HmsAuthenticationFilter(final AuthenticationManager authenticationManager,
	    final AuthenticationEntryPoint authenticationEntryPoint) {
	this.authenticationManager = authenticationManager;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.springframework.web.filter.OncePerRequestFilter#doFilterInternal(javax.
     * servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
     * javax.servlet.FilterChain)
     */
    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
	    final FilterChain chain) throws ServletException, IOException {
	final String header = request.getHeader("Authorization");

	if (header == null || !header.startsWith("Basic")) {
	    chain.doFilter(request, response);
	    return;
	}

	if (postOnly && !HttpMethod.POST.matches(request.getMethod())) {
	    throw new AuthenticationServiceException("Not allowed!" + request.getMethod());
	}

	final String grantType = request.getParameter("grant_type");

	if (grantType.equals("password")) {
	    try {
		passwordBasedAuthentication(request, response, chain);
	    } catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	    }
	} else if (grantType.equals("client_credentials")) {

	} else {
	    chain.doFilter(request, response);
	}
    }

    /**
     * Password based authentication.
     *
     * @param request  the request
     * @param response the response
     * @param chain    the chain
     * @throws Exception the exception
     */
    private void passwordBasedAuthentication(final HttpServletRequest request, final HttpServletResponse response,
	    final FilterChain chain) throws Exception {
	try {
	    String userName = request.getParameter("username");
	    String password = request.getParameter("password");

	    if (userName == null) {
		userName = "";
	    }

	    if (password == null) {
		password = "";
	    }

	    userName = userName.trim();

	    if (isAuthenticationNeeded(userName)) {
		final UsernamePasswordAuthenticationToken authenticationRequest;
		authenticationRequest = new UsernamePasswordAuthenticationToken(userName, password);
		authenticationRequest.setDetails(authenticationDetailsSource.buildDetails(request));

		final Authentication authenticatioResult = authenticationManager.authenticate(authenticationRequest);
		SecurityContextHolder.getContext().setAuthentication(authenticatioResult);

		rememberMeServices.loginSuccess(request, response, authenticatioResult);

		onSuccessfulAuthentication(request, response, authenticatioResult);
	    }
	} catch (AuthenticationException failed) {
	    SecurityContextHolder.clearContext();

	    rememberMeServices.loginFail(request, response);

	    if (ignoreFailure) {
		chain.doFilter(request, response);
	    } else {
		throw new Exception("Authentication failure");
	    }
	    return;
	}

	chain.doFilter(request, response);
    }

    /**
     * On successful authentication.
     *
     * @param request              the request
     * @param response             the response
     * @param authenticationResult the authentication result
     * @throws Exception the exception
     */
    private void onSuccessfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
	    final Authentication authenticationResult) throws Exception {
	final HttpSession session = request.getSession();

	List<SessionInformation> sessionInformations = sessionRegistry
		.getAllSessions(authenticationResult.getPrincipal(), false);

	Set<SessionInformation> expiredSessions = getExpiredSessions(sessionInformations, 1800000);

	closeSessions(sessionRegistry, expiredSessions);

	sessionInformations = sessionRegistry.getAllSessions(authenticationResult.getPrincipal(), false);

	if (sessionInformations != null && sessionInformations.size() >= 5) {
	    throw new Exception("Session limit exceeded!");
	}

	session.setMaxInactiveInterval(1800000 / 1000);
	sessionRegistry.registerNewSession(session.getId(), authenticationResult.getPrincipal());
    }

    /**
     * Gets the expired sessions.
     *
     * @param sessionInformations the session informations
     * @param maxIdleTime         the max idle time
     * @return the expired sessions
     */
    private Set<SessionInformation> getExpiredSessions(List<SessionInformation> sessionInformations, int maxIdleTime) {
	if (sessionInformations == null) {
	    return new HashSet<>();
	}
	return sessionInformations.stream()
		.filter(sessionInformation -> checkIfSessionExpired(sessionInformation.getLastRequest(), maxIdleTime))
		.collect(Collectors.toSet());
    }

    /**
     * Close sessions.
     *
     * @param sessionRegistry the session registry
     * @param expiredSessions the expired sessions
     */
    private void closeSessions(SessionRegistry sessionRegistry, Set<SessionInformation> expiredSessions) {
	if (sessionRegistry == null || expiredSessions == null) {
	    return;
	}

	expiredSessions.forEach(expiredSession -> {
	    if (expiredSession != null) {
		sessionRegistry.removeSessionInformation(expiredSession.getSessionId());
	    }
	});
    }

    /**
     * Check if session expired.
     *
     * @param date        the date
     * @param maxIdleTime the max idle time
     * @return true, if successful
     */
    private boolean checkIfSessionExpired(Date date, int maxIdleTime) {
	return (new Date().getTime() - date.getTime()) >= 1800000;
    }

    /**
     * Checks if is authentication needed.
     *
     * @param userName the user name
     * @return true, if is authentication needed
     */
    private boolean isAuthenticationNeeded(final String userName) {
	final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

	if (authentication == null || !authentication.isAuthenticated()) {
	    return true;
	}

	if (authentication instanceof UsernamePasswordAuthenticationToken
		&& !authentication.getName().equals(userName)) {
	    return true;
	}

	if (authentication instanceof AnonymousAuthenticationToken) {
	    return true;
	}

	return false;
    }
}

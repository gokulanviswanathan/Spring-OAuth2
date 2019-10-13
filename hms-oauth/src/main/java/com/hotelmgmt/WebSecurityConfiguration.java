package com.hotelmgmt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

import com.hotelmgmt.auth.logout.HmsLogoutHandler;
import com.hotelmgmt.auth.service.PreAuthenticatedUserDetailsService;
import com.hotelmgmt.auth.util.HmsUserAuthenticationProvider;

/**
 * The Class WebSecurityConfiguration.
 * 
 * @author Gokulan
 */
@Configuration
@Order(-1)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    /**
     * The token store.
     */
    @Autowired
    @Qualifier("tokenStore")
    private TokenStore tokenStore;

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.config.annotation.web.configuration.
     * WebSecurityConfigurerAdapter#configure(org.springframework.security.config.
     * annotation.authentication.builders.AuthenticationManagerBuilder)
     */
    @Override
    protected void configure(final AuthenticationManagerBuilder authenticationBuilder) throws Exception {
	authenticationBuilder.authenticationProvider(hmsUserAccountAuthenticationProvider())
		.authenticationProvider(preAuthAuthenticatedProvider());
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.config.annotation.web.configuration.
     * WebSecurityConfigurerAdapter#configure(org.springframework.security.config.
     * annotation.web.builders.HttpSecurity)
     */
    @Override
    protected void configure(final HttpSecurity http) throws Exception {
	http.formLogin().permitAll().and().requestMatchers()
		.antMatchers("/login", "/logout", "/", "/oauth/authorize", "/oauth/confirm_access",
			"/oauth/check_token", "/actuator/**")
		.and().csrf().disable().authorizeRequests().antMatchers("/").authenticated().and().logout()
		.clearAuthentication(true).invalidateHttpSession(true).logoutSuccessHandler(logoutHandler()).and()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).maximumSessions(5)
		.maxSessionsPreventsLogin(true).sessionRegistry(sessionRegistry());
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.config.annotation.web.configuration.
     * WebSecurityConfigurerAdapter#authenticationManagerBean()
     */
    @Override
    @Bean(name = "authenticationManager")
    public AuthenticationManager authenticationManagerBean() throws Exception {

	return super.authenticationManagerBean();
    }

    /**
     * Hms user authentication provider.
     *
     * @return the hms user authentication provider
     */
    @Bean
    public HmsUserAuthenticationProvider hmsUserAccountAuthenticationProvider() {
	return new HmsUserAuthenticationProvider();
    }

    @Bean(name = "sessionRegistry")
    public SessionRegistryImpl sessionRegistry() {
	return new SessionRegistryImpl();
    }

    @Bean
    public HmsLogoutHandler logoutHandler() {
	return new HmsLogoutHandler();
    }

    /**
     * Pre auth authenticated provider.
     *
     * @return the pre authenticated authentication provider
     */
    @Bean
    public PreAuthenticatedAuthenticationProvider preAuthAuthenticatedProvider() {
	final PreAuthenticatedAuthenticationProvider preAuthAuthenticatedProvider = new PreAuthenticatedAuthenticationProvider();
	preAuthAuthenticatedProvider.setPreAuthenticatedUserDetailsService(preauthenticatedDetailsService());

	return preAuthAuthenticatedProvider;
    }

    /**
     * Preauthenticated details service.
     *
     * @return the pre authenticated user details service
     */
    @Bean
    public PreAuthenticatedUserDetailsService preauthenticatedDetailsService() {
	return new PreAuthenticatedUserDetailsService(tokenStore);
    }
}

package com.hotelmgmt;

import javax.annotation.Resource;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

/**
 * The Class OAuth2ResourceServerConfiguration.
 * 
 * @author Gokulan
 */
@Configuration
@EnableResourceServer
public class OAuth2ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    /** The token services. */
    @Resource(name = "tokenServices")
    private DefaultTokenServices tokenServices;

    /** The authentication manager. */
    @Resource(name = "authenticationManager")
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(final ResourceServerSecurityConfigurer resources) {
	// @formatter:off
	resources.resourceId("hms-auth-resource").tokenServices(tokenServices)
		.authenticationManager(authenticationManager);
	// @formatter:on
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.oauth2.config.annotation.web.configuration.
     * ResourceServerConfigurerAdapter#configure(org.springframework.security.config
     * .annotation.web.builders.HttpSecurity)
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
	// @formatter:off
	http.authorizeRequests().anyRequest().authenticated().and().sessionManagement()
		.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).and().authorizeRequests()
		.antMatchers(HttpMethod.GET, "/**").access("#oauth2.hasScope('openid')")
		.antMatchers(HttpMethod.POST, "/**").access("#oauth2.hasScope('openid')")
		.antMatchers(HttpMethod.PATCH, "/**").access("#oauth2.hasScope('openid')")
		.antMatchers(HttpMethod.PUT, "/**").access("#oauth2.hasScope('openid')")
		.antMatchers(HttpMethod.DELETE, "/**").access("#oauth2.hasScope('openid')")
		.antMatchers(HttpMethod.OPTIONS, "/**").permitAll().and().exceptionHandling()
		.accessDeniedHandler(new OAuth2AccessDeniedHandler()).and().csrf().disable();
	// @formatter:on
    }

}

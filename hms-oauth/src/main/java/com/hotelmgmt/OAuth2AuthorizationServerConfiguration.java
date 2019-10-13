package com.hotelmgmt;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

import com.hotelmgmt.auth.filter.HmsAuthenticationFilter;
import com.hotelmgmt.auth.service.HmsClientInformationService;
import com.hotelmgmt.auth.util.HmsTokenEnhancer;

/**
 * The Class OAuth2AuthorizationServerConfiguration.
 * 
 * @author Gokulan
 */
@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    /**
     * The hms client information service.
     */
    @Autowired
    private HmsClientInformationService hmsClientInformationService;

    /**
     * The authentication manager.
     */
    @Autowired
    @Qualifier("authenticationManager")
    private AuthenticationManager authenticationManager;

    /**
     * The session registry.
     */
    @Autowired
    @Qualifier("sessionRegistry")
    private SessionRegistry sessionRegistry;

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.oauth2.config.annotation.web.configuration.
     * AuthorizationServerConfigurerAdapter#configure(org.springframework.security.
     * oauth2.config.annotation.web.configurers.
     * AuthorizationServerSecurityConfigurer)
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauth2Server) throws Exception {
	oauth2Server.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()")
		.authenticationEntryPoint(hmsAuthenticationEntryPoint());
	oauth2Server.addTokenEndpointAuthenticationFilter(hmsAuthenticationFilter());
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.oauth2.config.annotation.web.configuration.
     * AuthorizationServerConfigurerAdapter#configure(org.springframework.security.
     * oauth2.config.annotation.web.configurers.
     * AuthorizationServerEndpointsConfigurer)
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
	endpoints.userApprovalHandler(new DefaultUserApprovalHandler()).requestFactory(oauth2RequestFactory())
		.authorizationCodeServices(authorizationCodeServices()).tokenServices(tokenServices())
		.tokenEnhancer(hmsTokenEnhancer()).tokenGranter(tokenGranter())
		.accessTokenConverter(accessTokenConverter());
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.oauth2.config.annotation.web.configuration.
     * AuthorizationServerConfigurerAdapter#configure(org.springframework.security.
     * oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer)
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer allClients) throws Exception {
	allClients.withClientDetails(hmsClientInformationService).build();
    }

    /**
     * Token granter.
     *
     * @return the token granter
     * @throws Exception the exception
     */
    @Bean
    public TokenGranter tokenGranter() throws Exception {

	final TokenGranter[] tokenGranters = new TokenGranter[] {
		new ClientCredentialsTokenGranter(tokenServices(), hmsClientInformationService, oauth2RequestFactory()),
		new RefreshTokenGranter(tokenServices(), hmsClientInformationService, oauth2RequestFactory()),
		new ImplicitTokenGranter(tokenServices(), hmsClientInformationService, oauth2RequestFactory()),
		new ResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices(),
			hmsClientInformationService, oauth2RequestFactory())

	};

	return new CompositeTokenGranter(Arrays.asList(tokenGranters));
    }

    /**
     * Oauth 2 request factory.
     *
     * @return the o auth 2 request factory
     */
    @Bean
    public OAuth2RequestFactory oauth2RequestFactory() {
	return new DefaultOAuth2RequestFactory(hmsClientInformationService);
    }

    /**
     * Authorization code services.
     *
     * @return the authorization code services
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
	return new InMemoryAuthorizationCodeServices();
    }

    /**
     * Token services.
     *
     * @return the default token services
     * @throws Exception the exception
     */
    @Primary
    @Bean(name = "tokenServices")
    public DefaultTokenServices tokenServices() throws Exception {
	final DefaultTokenServices tokenServices = new DefaultTokenServices();

	tokenServices.setTokenStore(tokenStore());
	tokenServices.setSupportRefreshToken(true);
	tokenServices.setReuseRefreshToken(true);
	tokenServices.setClientDetailsService(hmsClientInformationService);
	tokenServices.setAuthenticationManager(authenticationManager);
	tokenServices.setTokenEnhancer(hmsTokenEnhancer());
	tokenServices.afterPropertiesSet();

	return tokenServices;
    }

    /**
     * Access token converter.
     *
     * @return the default access token converter
     */
    @Bean
    public DefaultAccessTokenConverter accessTokenConverter() {
	return new DefaultAccessTokenConverter();
    }

    /**
     * Hms token enhancer.
     *
     * @return the token enhancer
     */
    @Bean
    public TokenEnhancer hmsTokenEnhancer() {
	return new HmsTokenEnhancer();
    }

    /**
     * Token store.
     *
     * @return the token store
     */
    @Bean(name = "tokenStore")
    public TokenStore tokenStore() {
	return new InMemoryTokenStore();
    }

    /**
     * Hms authentication filter.
     *
     * @return the hms authentication filter
     */
    @Bean
    public HmsAuthenticationFilter hmsAuthenticationFilter() {
	return new HmsAuthenticationFilter(authenticationManager, hmsAuthenticationEntryPoint());
    }

    /**
     * Hms authentication enty point.
     *
     * @return the o auth 2 authentication entry point
     */
    @Bean
    public OAuth2AuthenticationEntryPoint hmsAuthenticationEntryPoint() {
	return new OAuth2AuthenticationEntryPoint();
    }

    /**
     * Password encoder.
     *
     * @return the password encoder
     */
    @Bean(name = "passwordEncoder")
    public PasswordEncoder passwordEncoder() {
	return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}

package com.hotelmgmt.auth.util;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;

/**
 * The Class HmsClientInformation.
 * 
 * @author Gokulan
 */
public class HmsClientInformation implements ClientDetails {

    private static final long serialVersionUID = 1L;

    private String clientId;
    private Set<String> resourceIds;
    private boolean isSecretRequired;
    private String clientSecret;
    private boolean isScoped;
    private Set<String> scope;
    private Set<String> authorizedGrantTypes;
    private Set<String> registeredRedirectUri;
    private Collection<GrantedAuthority> authorities;
    private Integer accessTokenValiditySeconds;
    private Integer refreshTokenValiditySeconds;
    private boolean isAutoApprove;
    private Map<String, Object> additionalInformation;

    public HmsClientInformation() {

    }

    @Override
    public String getClientId() {
	return clientId;
    }

    public void setClientId(String clientId) {
	this.clientId = clientId;
    }

    @Override
    public Set<String> getResourceIds() {
	return resourceIds;
    }

    public void setResourceIds(Set<String> resourceIds) {
	this.resourceIds = resourceIds;
    }

    @Override
    public boolean isSecretRequired() {
	return isSecretRequired;
    }

    public void setSecretRequired(boolean isSecretRequired) {
	this.isSecretRequired = isSecretRequired;
    }

    @Override
    public String getClientSecret() {
	return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
	this.clientSecret = clientSecret;
    }

    @Override
    public boolean isScoped() {
	return isScoped;
    }

    public void setScoped(boolean isScoped) {
	this.isScoped = isScoped;
    }

    @Override
    public Set<String> getScope() {
	return scope;
    }

    public void setScope(Set<String> scope) {
	this.scope = scope;
    }

    @Override
    public Set<String> getAuthorizedGrantTypes() {
	return authorizedGrantTypes;
    }

    public void setAuthorizedGrantTypes(Set<String> authorizedGrantTypes) {
	this.authorizedGrantTypes = authorizedGrantTypes;
    }

    @Override
    public Set<String> getRegisteredRedirectUri() {
	return registeredRedirectUri;
    }

    public void setRegisteredRedirecturi(Set<String> registeredRedirectUri) {
	this.registeredRedirectUri = registeredRedirectUri;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
	return authorities;
    }

    public void setAuthorities(Collection<GrantedAuthority> authorities) {
	this.authorities = authorities;
    }

    @Override
    public Integer getAccessTokenValiditySeconds() {
	return accessTokenValiditySeconds;
    }

    public void setAccessTokenValiditySeconds(Integer accessTokenValiditySeconds) {
	this.accessTokenValiditySeconds = accessTokenValiditySeconds;
    }

    @Override
    public Integer getRefreshTokenValiditySeconds() {
	return refreshTokenValiditySeconds;
    }

    public void setRefreshTokenValiditySeconds(Integer refreshTokenValiditySeconds) {
	this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
    }

    @Override
    public boolean isAutoApprove(final String scope) {
	return isAutoApprove;
    }

    public void setAutoApprove(boolean isAutoApprove) {
	this.isAutoApprove = isAutoApprove;
    }

    @Override
    public Map<String, Object> getAdditionalInformation() {
	return additionalInformation;
    }

    public void setAdditionalInformation(Map<String, Object> additionalInformation) {
	this.additionalInformation = additionalInformation;
    }

}

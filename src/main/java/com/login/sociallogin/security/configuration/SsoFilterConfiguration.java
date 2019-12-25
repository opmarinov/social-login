package com.login.sociallogin.security.configuration;

import com.login.sociallogin.security.resources.ClientResources;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.web.filter.CompositeFilter;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableOAuth2Client
public class SsoFilterConfiguration {

    private static final String GOOGLE_LOGIN_URL = "/login/google";
    private static final String GITHUB_LOGIN_URL = "/login/github";
    private static final String FACEBOOK_LOGIN_URL = "/login/facebook";

    @Autowired
    @Qualifier("oauth2ClientContext")
    private OAuth2ClientContext oauth2ClientContext;

    // creates a composite filter from the social ones.

    public CompositeFilter getFilter(){
        CompositeFilter filter = new CompositeFilter();
        List<OAuth2ClientAuthenticationProcessingFilter> filters = new ArrayList<>();

        filters.add(ssoFilter(google(), GOOGLE_LOGIN_URL));
        filters.add(ssoFilter(github(), GITHUB_LOGIN_URL));
        filters.add(ssoFilter(facebook(), FACEBOOK_LOGIN_URL));

        filter.setFilters(filters);
        return filter;
    }

    private OAuth2ClientAuthenticationProcessingFilter ssoFilter(ClientResources client, String path) {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);

        filter.setRestTemplate(template);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(
                client.getResource().getUserInfoUri(), client.getClient().getClientId());

        tokenServices.setRestTemplate(template);
        filter.setTokenServices(tokenServices);
        return filter;
    }

    // these bean are for initiating the resource / client data.

    @Bean
    @ConfigurationProperties("github")
    public ClientResources github() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("facebook")
    public ClientResources facebook() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("google")
    public ClientResources google() {
        return new ClientResources();
    }

    // registers the filter and adds execution priority.
    // it should be executed before the main security filter with order -100, according to spring boot doc.

    @Bean
    public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<OAuth2ClientContextFilter>();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }
}

package com.login.sociallogin.security.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private SsoFilterConfiguration ssoFilterConfiguration;


    /**
     * 1	All requests are protected by default
     * 2	The home page and login endpoints are explicitly excluded
     * 3	All other endpoints require an authenticated user
     * 4	Unauthenticated users are re-directed to the home page
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/**").authorizeRequests() // [ 1 ]
                .antMatchers("/", "/login**", "/webjars/**", "/error**").permitAll() // [ 2 ]
                .anyRequest().authenticated() // [ 3 ]
                .and().logout().logoutSuccessUrl("/").permitAll()
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and().exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")) // [ 4 ]
                .and().addFilterBefore(ssoFilterConfiguration.getFilter(), BasicAuthenticationFilter.class);
    }
}

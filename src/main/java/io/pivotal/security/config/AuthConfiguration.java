package io.pivotal.security.config;

import io.pivotal.security.oauth.AuditOAuth2AccessDeniedHandler;
import io.pivotal.security.oauth.AuditOAuth2AuthenticationExceptionHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.web.context.WebApplicationContext;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

@Configuration
@EnableResourceServer
@EnableWebSecurity
public class AuthConfiguration extends ResourceServerConfigurerAdapter {

  @Autowired
  ResourceServerProperties resourceServerProperties;

  @Autowired
  AuditOAuth2AuthenticationExceptionHandler auditOAuth2AuthenticationExceptionHandler;

  @Autowired
  SecurityProperties securityProperties;

  @Autowired
  AuditOAuth2AccessDeniedHandler auditOAuth2AccessDeniedHandler;

  @Override
  public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
    resources.resourceId(resourceServerProperties.getResourceId());
    resources.authenticationEntryPoint(auditOAuth2AuthenticationExceptionHandler);
    resources.accessDeniedHandler(auditOAuth2AccessDeniedHandler);
  }

  @Override
  public void configure(HttpSecurity http) throws Exception {
    http
//        .authorizeRequests()
//          .antMatchers("/info").permitAll()
//          .antMatchers("/health").permitAll()
//          .antMatchers("/api/v1/**").access("#oauth2.hasScope('credhub.read') and #oauth2.hasScope('credhub.write')")
        .httpBasic()
          .disable()
        .x509()
        .subjectPrincipalRegex("CN=(.*)")
        .userDetailsService(userDetails())
    .and()
    .authenticationProvider(new AuthenticationProvider() {
      @Override
      public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        int i = 1;
        return null;
      }

      @Override
      public boolean supports(Class<?> authentication) {
        return false;
      }
    });

  }

  private UserDetailsService userDetails() {
    return new UserDetailsService() {
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new User(username, username, Collections.emptyList());
      }
    };
  }

//  private X509AuthenticationFilter authenticationFilter() {
//    final X509AuthenticationFilter x509AuthenticationFilter = new X509AuthenticationFilter();
//    x509AuthenticationFilter.setPrincipalExtractor(extractor());
//    return x509AuthenticationFilter;
//  }
//
//  private X509PrincipalExtractor extractor() {
//    return new X509PrincipalExtractor() {
//      @Override
//      public Object extractPrincipal(X509Certificate cert) {
//        int i = 42;
//        return "iryna";
//      }
//    };
//  }
}

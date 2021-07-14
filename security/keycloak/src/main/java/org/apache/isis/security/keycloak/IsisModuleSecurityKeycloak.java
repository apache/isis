/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.apache.isis.security.keycloak;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.client.RestTemplate;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

import org.apache.isis.core.runtimeservices.IsisModuleCoreRuntimeServices;
import org.apache.isis.core.security.authentication.login.LoginSuccessHandler;
import org.apache.isis.core.security.authentication.manager.AuthenticationManager;
import org.apache.isis.core.webapp.IsisModuleCoreWebapp;
import org.apache.isis.security.keycloak.handler.KeycloakLogoutHandler;
import org.apache.isis.security.keycloak.services.KeycloakOauth2UserService;
import org.apache.isis.security.spring.IsisModuleSecuritySpring;

import lombok.RequiredArgsConstructor;
import lombok.val;

/**
 * Configuration Bean to support Isis Security using Shiro.
 *
 * @since 2.0 {@index}
 */
@Configuration
@Import({
        // modules
        IsisModuleCoreRuntimeServices.class,
        IsisModuleCoreWebapp.class,

        // builds on top of Spring
        IsisModuleSecuritySpring.class,

})
@EnableWebSecurity
@ComponentScan
public class IsisModuleSecurityKeycloak {

    @Bean
    public WebSecurityConfigurerAdapter webSecurityConfigurer(
            @Value("${kc.realm}") String realm,
            KeycloakOauth2UserService keycloakOidcUserService,
            KeycloakLogoutHandler keycloakLogoutHandler,
            List<LoginSuccessHandler> loginSuccessHandlers,
            List<LogoutHandler> logoutHandlers
            ) {
        return new WebSecurityConfigurerAdapter() {
            @Override
            public void configure(HttpSecurity http) throws Exception {

                val httpSecurityLogoutConfigurer =
                    http
                        .sessionManagement()
                            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .and()

                        .authorizeRequests()
                            .anyRequest().authenticated()
                        .and()

                        // Propagate logouts via /logout to Keycloak
                        .logout()
                            .addLogoutHandler(keycloakLogoutHandler)
                            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"));

                logoutHandlers.forEach(httpSecurityLogoutConfigurer::addLogoutHandler);

                httpSecurityLogoutConfigurer
                        .and()

                        // This is the point where OAuth2 login of Spring 5 gets enabled
                        .oauth2Login()
                            .defaultSuccessUrl("/wicket", true)
                            .successHandler(new AuthSuccessHandler(loginSuccessHandlers))
                            .userInfoEndpoint()
                            .oidcUserService(keycloakOidcUserService)
                        .and()

                        .loginPage(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/" + realm);
                ;
            }
        };
    }

    @Bean LoginSuccessHandler loginSuccessHandler(final AuthenticationManager authenticationManager) {
        return new LoginSuccessHandler() {
            @Override public void onSuccess() {

            }
        };
    }
    @RequiredArgsConstructor
    public static class AuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

        final List<LoginSuccessHandler> loginSuccessHandlers;

        @Override
        public void onAuthenticationSuccess(
                final HttpServletRequest request,
                final HttpServletResponse response,
                final Authentication authentication) throws ServletException, IOException {
            super.onAuthenticationSuccess(request, response, authentication);
            loginSuccessHandlers.forEach(LoginSuccessHandler::onSuccess);
        }
    }

    @Bean
    KeycloakOauth2UserService keycloakOidcUserService(OAuth2ClientProperties oauth2ClientProperties) {

        // TODO use default JwtDecoder - where to grab?
        val jwtDecoder = new NimbusJwtDecoderJwkSupport(
                oauth2ClientProperties.getProvider().get("keycloak").getJwkSetUri());

        val authoritiesMapper = new SimpleAuthorityMapper();
        authoritiesMapper.setConvertToUpperCase(true);

        return new KeycloakOauth2UserService(jwtDecoder, authoritiesMapper);
    }

    @Bean
    KeycloakLogoutHandler keycloakLogoutHandler() {
        return new KeycloakLogoutHandler(new RestTemplate());
    }

}


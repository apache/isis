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
package org.apache.isis.security.spring.webmodule;

import java.io.IOException;
import java.util.List;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;

import org.apache.isis.applib.services.iactnlayer.InteractionContext;
import org.apache.isis.applib.services.iactnlayer.InteractionService;
import org.apache.isis.applib.services.user.UserMemento;
import org.apache.isis.applib.services.user.UserMemento.AuthenticationSource;
import org.apache.isis.security.spring.authconverters.AuthenticationConverter;

import lombok.val;

/**
 * @since 2.0 {@index}
 */
//@Log4j2
public class SpringSecurityFilter implements Filter {

    @Autowired private InteractionService interactionService;
    @Inject List<AuthenticationConverter> converters;

    @Override
    public void doFilter(
            final ServletRequest servletRequest,
            final ServletResponse servletResponse,
            final FilterChain filterChain) throws IOException, ServletException {

        val httpServletResponse = (HttpServletResponse) servletResponse;

        val springAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if(springAuthentication==null
                || !springAuthentication.isAuthenticated()) {
            httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return; // not authenticated
        }

        UserMemento userMemento = null;
        for (final AuthenticationConverter converter : converters) {
            try {
                userMemento = converter.convert(springAuthentication);
                if(userMemento != null) {
                    break;
                }
            } catch(final Exception ignored) {
            }
        }

        if (userMemento == null) {
            httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return; // unknown principal type, not handled
        }

        // TODO: this should be added by Wicket viewer
        userMemento = userMemento.withRoleAdded("org.apache.isis.viewer.wicket.roles.USER")
                .withAuthenticationSource(AuthenticationSource.EXTERNAL);

        interactionService.run(
                InteractionContext.ofUserWithSystemDefaults(userMemento),
                ()->filterChain.doFilter(servletRequest, servletResponse));
    }

}

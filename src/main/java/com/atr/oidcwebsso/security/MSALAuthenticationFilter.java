package com.atr.oidcwebsso.security;

/*import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.OnBehalfOfParameters;
import com.microsoft.aad.msal4j.UserAssertion;
import com.microsoft.azure.spring.autoconfigure.aad.UserPrincipal;*/

public class MSALAuthenticationFilter {/* extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(MSALAuthenticationFilter.class);
    private static final String TOKEN_HEADER = "Authorization";
    private static final String TOKEN_TYPE = "Bearer ";

    // Properties from the application.properties file like clientId, tenant and stuff.

    private static final String CURRENT_USER_PRINCIPAL = "CURRENT_USER_PRINCIPAL";
    private static final String CURRENT_USER_ACCESS_TOKEN = "CURRENT_USER_ACCESS_TOKEN";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader(TOKEN_HEADER);
        UserPrincipal principal = (UserPrincipal) request.getSession().getAttribute(CURRENT_USER_PRINCIPAL);

        if (authHeader != null && authHeader.startsWith(TOKEN_TYPE)) {
            try {
                final String idToken = authHeader.replace(TOKEN_TYPE, "");

                ConfidentialClientApplication clientApplication = ConfidentialClientApplication.builder(
                        clientId,
                        ClientCredentialFactory.create(clientSecret))
                        .authority(authority)
                        .build();

                Set<String> scopes = new HashSet<>(Arrays.asList(scope.split(" ")));
                UserAssertion assertion = new UserAssertion(idToken);

                OnBehalfOfParameters params = OnBehalfOfParameters.builder(scopes, assertion).build();
                CompletableFuture<AuthenticationResult> future = clientApplication.acquireToken(params);

                AuthenticationResult accessToken = future.get();

                if (principal == null) {
                    principal = principalManager.buildUserPrincipal(idToken, accessToken);

                    request.getSession().setAttribute(CURRENT_USER_PRINCIPAL, principal);
                    request.getSession().setAttribute(CURRENT_USER_ACCESS_TOKEN, accessToken);
                }
                final Authentication authentication = new PreAuthenticatedAuthenticationToken(
                        principal,
                        null,
                        convertGroupsToGrantedAuthorities(principal.getUserGroups()));

                authentication.setAuthenticated(true);
                log.info("Request token verification success. {}", authentication);
                SecurityContextHolder.getContext().setAuthentication(authentication);


            }
            catch (MalformedURLException | InterruptedException | ExecutionException ex) {
                log.error("Failed to authenticate", ex);
                throw new ServletException(ex);
            }

        }    
        filterChain.doFilter(request, response);
    }    */
}
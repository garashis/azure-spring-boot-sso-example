package com.example.demo;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.util.RedirectUrlBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
class SecurityConfiguration {

    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {

        //OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        //authenticationProvider.setResponseAuthenticationConverter(groupsConverter());
        LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint =  new LoginUrlAuthenticationEntryPoint("/saml2/authenticate/azure");
        //loginUrlAuthenticationEntryPoint.setForceHttps(true);
        //loginUrlAuthenticationEntryPoint.setUseForward(true);
        // @formatter:off
        http
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(loginUrlAuthenticationEntryPoint)
                )

                .authorizeRequests(authorize ->
                        authorize.antMatchers("/favicon.ico").permitAll().
                                anyRequest().authenticated()
                ).saml2Login(saml2 -> saml2.successHandler((request, response, authentication) -> {
                    DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
                    //redirectStrategy.setContextRelative(false);

                    PortMapper portMapper = new PortMapperImpl();
                    PortResolver portResolver = new PortResolverImpl();
                    int serverPort = portResolver.getServerPort(request);
                    Integer httpsPort = portMapper.lookupHttpsPort(serverPort);
                    RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
                    urlBuilder.setScheme("https");
                    urlBuilder.setServerName(request.getServerName());
                    urlBuilder.setPort(httpsPort);
                    urlBuilder.setContextPath(request.getContextPath());
                    /*urlBuilder.setServletPath(request.getServletPath());
                    urlBuilder.setPathInfo(request.getPathInfo());
                    urlBuilder.setQuery(request.getQueryString());*/
                    redirectStrategy.sendRedirect(request, response, urlBuilder.getUrl());
                }))
                //.and()
           /*.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/favicon.ico")
                    .permitAll()
                .anyRequest().authenticated()
            )
            .saml2Login(saml2 -> saml2
                .authenticationManager(new ProviderManager(authenticationProvider))
                           // .getAuthenticationEntryPoint
                    //.authenticationRequestUri("https://{baseHost}{basePort}{basePath}/login"+ Saml2AuthenticationRequestResolver.DEFAULT_AUTHENTICATION_REQUEST_URI)
            )*/

            .saml2Logout(withDefaults());

        // @formatter:on

        return http.build();
    }

    private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> groupsConverter() {

        Converter<ResponseToken, Saml2Authentication> delegate =
            OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

        return (responseToken) -> {
            Saml2Authentication authentication = delegate.convert(responseToken);
            Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
            List<String> groups = principal.getAttribute("groups");
            Set<GrantedAuthority> authorities = new HashSet<>();
            if (groups != null) {
                groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
            } else {
                authorities.addAll(authentication.getAuthorities());
            }
            return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
        };
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
                new SavedRequestAwareAuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
                        super.onAuthenticationSuccess(request, response, authentication);
                    }
                };
        successRedirectHandler.setDefaultTargetUrl("/");
        return successRedirectHandler;
    }
}

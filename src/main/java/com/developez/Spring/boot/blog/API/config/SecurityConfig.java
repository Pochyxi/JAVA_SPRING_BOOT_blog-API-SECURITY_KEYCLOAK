package com.developez.Spring.boot.blog.API.config;


import com.developez.Spring.boot.blog.API.filter.CsrfCookieFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {


    @Bean
    SecurityFilterChain securityFilterChain( HttpSecurity http ) throws Exception {
        // CSRF TOKEN DISABILITATO
//        // Crea un nuovo gestore di attributi di richiesta CSRF
//        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
//        // Imposta il nome dell'attributo della richiesta CSRF a "_csrf"
//        requestHandler.setCsrfRequestAttributeName( "_csrf" );

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

        http
                .sessionManagement(session -> session
                        .sessionCreationPolicy( SessionCreationPolicy.STATELESS )
                )
                // Configura CORS
                .cors( ( httpSecurityCorsConfigurer ) -> httpSecurityCorsConfigurer
                        .configurationSource( ( httpServletRequest ) -> {
                            // Crea una nuova configurazione CORS
                            CorsConfiguration corsConfiguration = new CorsConfiguration();
                            // Consente le richieste da "http://localhost:4200" e per sicurezza aggiungiamo anche
                            // "http://127.0.0.1:4200" che è l'indirizzo IP di localhost Angular
                            corsConfiguration.setAllowedOrigins( List.of( "http://127.0.0.1:4200/", "http://localhost:4200/" ) );
                            // Consente tutti i metodi HTTP
                            corsConfiguration.setAllowedMethods( List.of("GET", "POST", "PUT", "DELETE", "HEAD",
                                    "OPTIONS"));
                            // Consente tutti gli header
                            corsConfiguration.setAllowedHeaders( List.of( "*" ) );
                            // Consente le credenziali
                            corsConfiguration.setAllowCredentials( true );
                            corsConfiguration.setExposedHeaders( Arrays.asList( "Authorization", "X-XSRF-TOKEN" ) );
                            // Imposta l'età massima del risultato preflight (in secondi) a 3600
                            corsConfiguration.setMaxAge( 3600L );
                            return corsConfiguration;
                        } )
                )
                // CSRF TOKEN DISABILITATO
                .csrf().disable()
                // CSRF TOKEN DISABILITATO
                // Aggiunge il filtro CSRF personalizzato dopo il filtro di autenticazione di base
//                .addFilterAfter(
//                        new CsrfCookieFilter(), UsernamePasswordAuthenticationFilter.class
//                )
                .authorizeHttpRequests((authorize) -> {

                    authorize.requestMatchers( HttpMethod.GET, "/api/**").permitAll()
                            .requestMatchers( "/api/auth/**" ).permitAll()
                            .anyRequest().authenticated();
                })// Configura la gestione del login tramite form oauth2
                .oauth2ResourceServer( ( oauth2RS ) -> oauth2RS
                        .jwt( ( jwt ) -> jwt
                                .jwtAuthenticationConverter( jwtAuthenticationConverter )
                        )
                );

        return http.build();
    }
}

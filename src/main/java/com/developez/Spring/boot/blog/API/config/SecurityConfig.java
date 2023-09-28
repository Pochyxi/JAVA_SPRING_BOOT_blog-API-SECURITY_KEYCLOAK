package com.developez.Spring.boot.blog.API.config;

import com.developez.Spring.boot.blog.API.Security.JwtAuthenticationEntryPoint;
import com.developez.Spring.boot.blog.API.Security.JwtAuthenticationFilter;
import com.developez.Spring.boot.blog.API.filter.CsrfCookieFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private UserDetailsService userDetailsService;

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    SecurityConfig( UserDetailsService userDetailsService,
                    JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                    JwtAuthenticationFilter jwtAuthenticationFilter){
        this.userDetailsService = userDetailsService;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager( AuthenticationConfiguration configuration ) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public static PasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain securityFilterChain( HttpSecurity http ) throws Exception {

        // Crea un nuovo gestore di attributi di richiesta CSRF
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        // Imposta il nome dell'attributo della richiesta CSRF a "_csrf"
        requestHandler.setCsrfRequestAttributeName( "_csrf" );

        http
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
                .csrf( ( httpSecurityCsrfConfigurer ) -> httpSecurityCsrfConfigurer
                        // Imposta il gestore di attributi di richiesta CSRF
                        .csrfTokenRequestHandler( requestHandler )
                        // Ignora la protezione CSRF per i percorsi "/contact" e "/register"
                        .ignoringRequestMatchers( "/api/auth/login", "/api/auth/register", "/api/auth/signin", "/api/auth/signup" )
                        // Utilizza un repository di token CSRF basato su cookie con l'opzione HttpOnly disabilitata
                        .csrfTokenRepository( CookieCsrfTokenRepository.withHttpOnlyFalse() )
                )
                // Aggiunge il filtro CSRF personalizzato dopo il filtro di autenticazione di base
                .addFilterAfter(
                        new CsrfCookieFilter(), UsernamePasswordAuthenticationFilter.class
                )
                .authorizeHttpRequests((authorize) -> {

                    authorize.requestMatchers( HttpMethod.GET, "/api/**").permitAll()
//                            .requestMatchers( HttpMethod.GET, "/api/categories/**").permitAll()
                            .requestMatchers( "/api/auth/**" ).permitAll()
                            .anyRequest().authenticated();
                }).exceptionHandling( exception -> exception
                        .authenticationEntryPoint( jwtAuthenticationEntryPoint )
                ).sessionManagement(session -> session
                        .sessionCreationPolicy( SessionCreationPolicy.STATELESS )
                );

        http.addFilterBefore( jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class );

        return http.build();
    }
}

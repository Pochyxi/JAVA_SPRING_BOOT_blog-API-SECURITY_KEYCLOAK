package com.developez.Spring.boot.blog.API.Security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter( JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailsService ) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal( HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain ) throws ServletException, IOException {


        // Estrarre il token JWT dallo header di autorizzazione
        String token = getTokenFromRequest( request );

        // Verifica se il token JWT è valido
        if( StringUtils.hasText( token ) && jwtTokenProvider.validateToken( token ) ) {

            // Recupera il nome utente dal token JWT
            String username = jwtTokenProvider.getUsernameFromJWT( token );

            // Recupera i dettagli dell'utente dal nome utente
            UserDetails userDetails = userDetailsService.loadUserByUsername( username );

            // Crea un'istanza di UsernamePasswordAuthenticationToken
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
            authenticationToken.setDetails( new WebAuthenticationDetailsSource().buildDetails( request ) );

            // Imposta l'istanza di UsernamePasswordAuthenticationToken nel contesto di sicurezza
            SecurityContextHolder.getContext().setAuthentication( authenticationToken );
        }

        filterChain.doFilter( request, response );

    }

    private String getTokenFromRequest( HttpServletRequest request ) {
        String bearerToken = request.getHeader( "Authorization" );

        // Verifica se il token JWT è presente nello header di autorizzazione
        if( StringUtils.hasText( bearerToken ) && bearerToken.startsWith( "Bearer " ) ) {
            // Ritorna il token JWT
            return bearerToken.substring( 7 );
        }

        return null;
    }
}

package com.developez.Spring.boot.blog.API.Security;

import com.developez.Spring.boot.blog.API.exception.BlogAPIException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value( "${app.jwt-secret}" )
    private String jwtSecret;

    @Value( "${app-jwt-expiration-milliseconds}" )
    private long jwtExpirationInMs;

    // Generazione del token JWT
    public String generateToken( Authentication authentication ) {
        String username = authentication.getName();

        Date currentDate = new Date();

        Date expirationDate = new Date( currentDate.getTime() + jwtExpirationInMs );

        // Ritorna il token JWT
        return Jwts.builder()
                .setSubject( username )
                .setIssuedAt( new Date() )
                .setExpiration( expirationDate )
                .signWith( key() )
                .compact();

    }

    // Recupero della chiave segreta
    private Key key() {
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode( jwtSecret )
        );
    }

    // Recupero del nome utente dal token JWT
    public String getUsernameFromJWT( String token ) {
        // Recupero il nome utente dal token JWT
        Claims claims = Jwts.parserBuilder()
                .setSigningKey( key() )
                .build()
                .parseClaimsJws( token )
                .getBody();

        // Ritorna il nome utente
        return claims.getSubject();
    }

    // Verifica se il token JWT è valido
    public boolean validateToken( String authToken ) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey( key() )
                    .build()
                    .parse( authToken );
            return true;
        } catch( MalformedJwtException ex ) {
            throw new BlogAPIException( HttpStatus.BAD_REQUEST, "Token JWT non valido" );
        } catch( ExpiredJwtException ex ) {
            throw new BlogAPIException( HttpStatus.BAD_REQUEST, "Token JWT scaduto" );
        } catch( UnsupportedJwtException ex ) {
            throw new BlogAPIException( HttpStatus.BAD_REQUEST, "Token JWT non supportato" );
        } catch( IllegalArgumentException ex ) {
            throw new BlogAPIException( HttpStatus.BAD_REQUEST, "Token JWT vuoto" );
        }
    }

}

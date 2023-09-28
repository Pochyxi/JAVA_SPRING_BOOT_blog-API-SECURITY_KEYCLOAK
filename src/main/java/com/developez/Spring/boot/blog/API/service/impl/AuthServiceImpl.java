package com.developez.Spring.boot.blog.API.service.impl;

import com.developez.Spring.boot.blog.API.Security.JwtTokenProvider;
import com.developez.Spring.boot.blog.API.entity.Role;
import com.developez.Spring.boot.blog.API.entity.User;
import com.developez.Spring.boot.blog.API.exception.BlogAPIException;
import com.developez.Spring.boot.blog.API.payload.LoginDto;
import com.developez.Spring.boot.blog.API.payload.SignupDto;
import com.developez.Spring.boot.blog.API.repository.RoleRepository;
import com.developez.Spring.boot.blog.API.repository.UserRepository;
import com.developez.Spring.boot.blog.API.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public AuthServiceImpl(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenProvider jwtTokenProvider
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public String Login( LoginDto loginDto ) {

        Authentication authentication =
                authenticationManager.authenticate( new UsernamePasswordAuthenticationToken( loginDto.getUsernameOrEmail(),
                loginDto.getPassword() ) );

        // Impostare l'oggetto di autenticazione
        SecurityContextHolder.getContext().setAuthentication( authentication );

        // Generazione del token JWT
        return jwtTokenProvider.generateToken( authentication );
    }

    @Override
    public String signup( SignupDto signupDto ) {

        // Aggiungiere un controllo per verificare se l'utente esiste già
        if( userRepository.existsByUsername( signupDto.getUsername() ) ) {
            throw new BlogAPIException( HttpStatus.BAD_REQUEST, "Username attualmente esistente" );
        }

        // Aggiungiere un controllo per verificare se l'email esiste già
        if( userRepository.existsByEmail( signupDto.getEmail() ) ) {
            throw new BlogAPIException( HttpStatus.BAD_REQUEST, "Email attualmente esistente" );
        }

        // Creare un nuovo utente
        User user = new User();
        user.setName( signupDto.getName() );
        user.setUsername( signupDto.getUsername() );
        user.setEmail( signupDto.getEmail() );
        // Impostare la password criptata
        user.setPassword( passwordEncoder.encode( signupDto.getPassword() ) );

        // Impostare il ruolo dell'utente
        Set<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByName( "ROLE_USER" ).orElseThrow( () -> new BlogAPIException( HttpStatus.BAD_REQUEST, "Ruolo non trovato" ) );
        roles.add( userRole );
        user.setRoles( roles );

        // Salvare l'utente
        userRepository.save( user );


        return "Utente registrato con successo";
    }
}

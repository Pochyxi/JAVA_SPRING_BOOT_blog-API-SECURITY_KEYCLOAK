package com.developez.Spring.boot.blog.API.controller;

import com.developez.Spring.boot.blog.API.payload.JwtAuthResponse;
import com.developez.Spring.boot.blog.API.payload.LoginDto;
import com.developez.Spring.boot.blog.API.payload.SignupDto;
import com.developez.Spring.boot.blog.API.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController( AuthService authService ) {
        this.authService = authService;
    }

    // Costruzione della login REST API
    @PostMapping(value = {"/login", "/signing"})
    public ResponseEntity<JwtAuthResponse> login(@RequestBody LoginDto loginDto ) {
        String token = authService.Login( loginDto );

        JwtAuthResponse jwtAuthResponse = new JwtAuthResponse();
        jwtAuthResponse.setAccessToken( token );

        return new ResponseEntity<>( jwtAuthResponse, HttpStatus.OK );
    }

    // Costruzione della signup REST API
    @PostMapping(value = {"/register", "/signup"} )
    public ResponseEntity<String> signup(@RequestBody SignupDto signupDto ) {
        String response = authService.signup( signupDto );

        return new ResponseEntity<>( response, HttpStatus.CREATED );
    }


}

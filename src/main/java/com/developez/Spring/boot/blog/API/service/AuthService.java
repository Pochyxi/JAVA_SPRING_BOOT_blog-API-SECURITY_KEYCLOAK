package com.developez.Spring.boot.blog.API.service;

import com.developez.Spring.boot.blog.API.payload.LoginDto;
import com.developez.Spring.boot.blog.API.payload.SignupDto;

public interface AuthService {

    String Login( LoginDto loginDto );
    String signup( SignupDto signupDto );
}

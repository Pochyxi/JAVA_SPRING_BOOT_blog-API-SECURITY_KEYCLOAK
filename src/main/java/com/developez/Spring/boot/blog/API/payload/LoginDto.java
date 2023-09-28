package com.developez.Spring.boot.blog.API.payload;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LoginDto {

    private String usernameOrEmail;
    private String password;
}

package com.developez.Spring.boot.blog.API.payload;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CommentDto {
    private Long id;

    // Il nome non dovrebbe essere vuoto o null
    @NotEmpty(message = "Il nome non può essere vuoto")
    private String name;

    // l'email non dovrebbe essere vuoto o null
    // validazione email
    @NotEmpty(message = "Email non dovrebbe essere vuoto")
    @Email
    private String email;

    // Il body non dovrebbe essere vuoto o null
    // Il body non dovrebbe essere più corto di 10 caratteri
    @NotEmpty(message = "Il body non può essere vuoto")
    @Size(min = 10, message = "Il body dovrebbe essere di almeno 10 caratteri")
    private String body;
}

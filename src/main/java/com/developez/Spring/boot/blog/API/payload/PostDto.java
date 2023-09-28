package com.developez.Spring.boot.blog.API.payload;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.Set;

@Data
public class PostDto {
    private Long id;

    // Il titolo non deve essere null o essere vuoto
    // Il titolo non deve essere più corto di 2 caratteri
    @NotEmpty
    @Size(min = 2, message = "Il titolo del Post dovrebbe essere di almeno 2 caratteri")
    private String title;

    // La descrizione non deve essere null o essere vuota
    // La descrizione non deve essere più corta di 10 caratteri
    @NotEmpty
    @Size(min = 10, message = "La descrizione del Post dovrebbe essere di almeno 10 caratteri")
    private String description;

    // Il contenuto non deve essere null o essere vuoto
    @NotEmpty
    private String content;

    private Set<CommentDto> comments;

    private Long categoryId;
}

package com.developez.Spring.boot.blog.API.controller;

import com.developez.Spring.boot.blog.API.payload.PostDto;
import com.developez.Spring.boot.blog.API.payload.PostResponse;
import com.developez.Spring.boot.blog.API.service.PostService;
import com.developez.Spring.boot.blog.API.utils.AppConstants;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/posts")
public class PostController {

    private final PostService postService;

    @Autowired
    public PostController(PostService postService){
        this.postService = postService;
    }

    // Creazione di un Post
    @PreAuthorize( "hasRole('ADMIN')" )
    @PostMapping
    public ResponseEntity<PostDto> createPost(@Valid @RequestBody PostDto postDto ){
        return new ResponseEntity<>( postService.createPost( postDto ), HttpStatus.CREATED );
    }

    // Recupero di tutti i Post con paginazione e oggetto PostResponse
    // Utilizzo del sorting
    // Utilizzo di sort direction
    // Utilizzo di AppConstants
    @GetMapping
    public ResponseEntity<PostResponse> getAllPosts(
            @RequestParam(value = "pageNo", defaultValue = AppConstants.DEFAULT_PAGE_NUMBER) int pageNo,
            @RequestParam(value = "pageSize", defaultValue = AppConstants.DEFAULT_PAGE_SIZE) int pageSize,
            @RequestParam(value = "sortBy", defaultValue = AppConstants.DEFAULT_SORT_BY, required = false) String sortBy,
            @RequestParam(value = "sortDir", defaultValue = AppConstants.DEFAULT_SORT_DIRECTION, required = false) String sortDir
    ){
        return new ResponseEntity<>( postService.getAllPosts(pageNo, pageSize, sortBy, sortDir), HttpStatus.OK );
    }

    // Recupero di un Post tramite ID
    @GetMapping("/{id}")
    public ResponseEntity<PostDto> getPostById( @PathVariable("id") Long id ){
        return new ResponseEntity<>( postService.getPostById( id ), HttpStatus.OK );
    }

    // Aggiornamento di un Post tramite ID
    @PreAuthorize( "hasRole('ADMIN')" )
    @PutMapping("/{id}")
    public ResponseEntity<PostDto> updatePost(@Valid @RequestBody PostDto postDto, @PathVariable("id") Long id ){
        return new ResponseEntity<>( postService.updatePost( postDto, id ), HttpStatus.OK );
    }

    // Eliminazione di un Post tramite ID
    @DeleteMapping("/{id}")
    @PreAuthorize( "hasRole('ADMIN')" )
    public ResponseEntity<String> deletePostById( @PathVariable("id") Long id ){
        postService.deletePostById( id );
        return new ResponseEntity<>( "Post eliminato con successo.", HttpStatus.OK );
    }

    // Recupero di tutti i Post tramite ID di Category
    // http://localhost:8080/api/posts/category/{{categoryId}}
    @GetMapping("/category/{categoryId}")
    public ResponseEntity<List<PostDto>> getPostsByCategory(@PathVariable("categoryId") Long categoryId) {
        return ResponseEntity.ok( postService.getAllPostsByCategoryId( categoryId ) );
    }
}

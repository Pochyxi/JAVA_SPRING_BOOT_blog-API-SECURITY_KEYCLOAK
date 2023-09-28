package com.developez.Spring.boot.blog.API.controller;

import com.developez.Spring.boot.blog.API.payload.CategoryDto;
import com.developez.Spring.boot.blog.API.service.CategoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/categories")
public class CategoryController {

    private final CategoryService categoryService;

    @Autowired
    public CategoryController( CategoryService categoryService ) {
        this.categoryService = categoryService;
    }

    // Costruzione della addCategory REST API
    @PostMapping
    @PreAuthorize( "hasRole('ADMIN')" )
    public ResponseEntity<CategoryDto> addCategory(@RequestBody CategoryDto categoryDto ) {
        CategoryDto response = categoryService.addCategory( categoryDto );

        return new ResponseEntity<>( response, HttpStatus.CREATED );
    }

    // Costruzione della getCategory REST API
    @GetMapping("/{categoryId}")
    public ResponseEntity<CategoryDto> getCategory(@PathVariable("categoryId") Long categoryId ) {
        CategoryDto response = categoryService.getCategory( categoryId );

        return new ResponseEntity<>( response, HttpStatus.OK );
    }

    // Costruzione della getAllCategories REST API
    @GetMapping
    public ResponseEntity<List<CategoryDto>> getAllCategories() {
        return ResponseEntity.ok( categoryService.getAllCategories() );
    }

    // Costruzione della updateCategory REST API
    @PutMapping("/{categoryId}")
    @PreAuthorize( "hasRole('ADMIN')" )
    public ResponseEntity<CategoryDto> updateCategory(@RequestBody CategoryDto categoryDto, @PathVariable("categoryId") Long categoryId ) {
        CategoryDto response = categoryService.updateCategory( categoryDto, categoryId );

        return new ResponseEntity<>( response, HttpStatus.OK );
    }

    // Costruzione della deleteCategory REST API
    @DeleteMapping("/{categoryId}")
    @PreAuthorize( "hasRole('ADMIN')" )
    public ResponseEntity<String> deleteCategory(@PathVariable("categoryId") Long categoryId ) {
        categoryService.deleteCategory( categoryId );

        return new ResponseEntity<>( "Categoria eliminata con successo", HttpStatus.OK );
    }

}

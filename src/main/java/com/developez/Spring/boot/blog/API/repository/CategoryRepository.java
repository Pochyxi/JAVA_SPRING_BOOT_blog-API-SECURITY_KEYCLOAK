package com.developez.Spring.boot.blog.API.repository;

import com.developez.Spring.boot.blog.API.entity.Category;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CategoryRepository extends JpaRepository<Category, Long> {
}

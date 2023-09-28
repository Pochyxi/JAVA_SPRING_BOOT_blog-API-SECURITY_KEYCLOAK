package com.developez.Spring.boot.blog.API.repository;

import com.developez.Spring.boot.blog.API.entity.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PostRepository extends JpaRepository<Post, Long> {

    List<Post> findAllByCategoryId( Long categoryId );
}

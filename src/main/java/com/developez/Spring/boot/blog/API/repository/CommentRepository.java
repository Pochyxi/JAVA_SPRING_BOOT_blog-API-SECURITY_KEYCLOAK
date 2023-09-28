package com.developez.Spring.boot.blog.API.repository;

import com.developez.Spring.boot.blog.API.entity.Comment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CommentRepository extends JpaRepository<Comment, Long> {
    List<Comment> findByPostId( Long postId );
}

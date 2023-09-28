package com.developez.Spring.boot.blog.API.service.impl;

import com.developez.Spring.boot.blog.API.entity.Comment;
import com.developez.Spring.boot.blog.API.entity.Post;
import com.developez.Spring.boot.blog.API.exception.BlogAPIException;
import com.developez.Spring.boot.blog.API.exception.ResourceNotFoundException;
import com.developez.Spring.boot.blog.API.payload.CommentDto;
import com.developez.Spring.boot.blog.API.repository.CommentRepository;
import com.developez.Spring.boot.blog.API.repository.PostRepository;
import com.developez.Spring.boot.blog.API.service.CommentService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CommentServiceImpl implements CommentService {

    private final CommentRepository commentRepository;
    private final PostRepository postRepository;

    private ModelMapper mapper;

    @Autowired
    public CommentServiceImpl( CommentRepository commentRepository,
                               PostRepository postRepository,
                               ModelMapper mapper) {
        this.commentRepository = commentRepository;
        this.postRepository = postRepository;
        this.mapper = mapper;
    }

    // Creare un commento
    @Override
    public CommentDto createComment( long postId, CommentDto commentDto ) {
        Comment comment = mapToEntity( commentDto );

        // Ricavare l'esistenza del post
        Post post = postRepository.findById( postId ).orElseThrow( () -> new ResourceNotFoundException( "Post", "id", postId ) );

        // Impostare il post al commento
        comment.setPost( post );

        // Salvare il commento
        Comment savedComment = commentRepository.save( comment );

        return mapToDto( savedComment);
    }

    // Recuperare tutti i commenti di un post
    @Override
    public List<CommentDto> getCommentsByPostId( long postId ) {
        List<Comment> comments = commentRepository.findByPostId( postId );

        return comments.stream().map( this::mapToDto ).collect( Collectors.toList());
    }

    // Recuperare un commento di un post
    @Override
    public CommentDto getCommentById( long postId, long commentId ) {

        Comment comment = isCommentOfPost( postId, commentId, "Il commento non appartiene al Post con id " );

        return mapToDto( comment );
    }

    // Modificare un commento di un post
    @Override
    public CommentDto updateComment( long postId, long commentId, CommentDto commentDto ) {

        Comment comment = isCommentOfPost( postId, commentId, "Non puoi modificare questo commento perchè non appartiene al Post con id " );

        comment.setName( commentDto.getName() );
        comment.setEmail( commentDto.getEmail() );
        comment.setBody( commentDto.getBody() );

        Comment updatedComment = commentRepository.save( comment );

        return mapToDto( updatedComment );
    }

    // Eliminare un commento appartentente a un post
    @Override
    public void deleteComment( Long postId, Long commentId ) {

        Comment comment = isCommentOfPost( postId, commentId, "Non puoi eliminare questo commento perchè non appartiene al Post con id " );

        commentRepository.delete( comment );
    }

    private Comment isCommentOfPost( Long postId, Long commentId, String errorMessage) {
        Post post = postRepository.findById( postId ).orElseThrow( () -> new ResourceNotFoundException( "Post", "id", postId ) );

        Comment comment = commentRepository.findById( commentId ).orElseThrow( () -> new ResourceNotFoundException( "Comment", "id", commentId ) );

        if (!comment.getPost().getId().equals( post.getId() )) {
            throw new BlogAPIException( HttpStatus.BAD_REQUEST, errorMessage + postId );
        }

        return comment;
    }

    // Mappatura di un commento in DTO
    private CommentDto mapToDto( Comment comment ) {

        return mapper.map( comment, CommentDto.class );
    }

    // Mappatura di un DTO in commento
    private Comment mapToEntity( CommentDto commentDto ) {

        return mapper.map( commentDto, Comment.class );
    }
}

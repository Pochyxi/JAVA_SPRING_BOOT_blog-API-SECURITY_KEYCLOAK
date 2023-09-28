package com.developez.Spring.boot.blog.API.service.impl;

import com.developez.Spring.boot.blog.API.entity.Category;
import com.developez.Spring.boot.blog.API.entity.Post;
import com.developez.Spring.boot.blog.API.exception.ResourceNotFoundException;
import com.developez.Spring.boot.blog.API.payload.PostDto;
import com.developez.Spring.boot.blog.API.payload.PostResponse;
import com.developez.Spring.boot.blog.API.repository.CategoryRepository;
import com.developez.Spring.boot.blog.API.repository.PostRepository;
import com.developez.Spring.boot.blog.API.service.PostService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PostServiceImpl implements PostService {

    private final PostRepository postRepository;

    private final ModelMapper modelMapper;

    private final CategoryRepository categoryRepository;

    @Autowired
    public PostServiceImpl( PostRepository postRepository,
                            ModelMapper mapper,
                            CategoryRepository categoryRepository) {

        this.postRepository = postRepository;
        this.modelMapper = mapper;
        this.categoryRepository = categoryRepository;
    }

    // Creazione di un Post
    @Override
    public PostDto createPost( PostDto postDto ) {

        Category category = categoryRepository.findById( postDto.getCategoryId() )
                .orElseThrow(() -> new ResourceNotFoundException("Category", "id", postDto.getCategoryId()));

        // Convertire il DTO in ENTITY
        Post post = modelMapper.map( postDto, Post.class );

        // Settare la Category
        post.setCategory( category );

        // Salvare l'ENTITY nel DB
        Post savedPost = postRepository.save( post );

        // Convertire l'ENTITY in DTO
        return modelMapper.map( savedPost, PostDto.class );
    }

    // Recupero di tutti i Post con paginazione e oggetto PostResponse
    // Utilizzo del sorting
    // Utilizzo di sort direction
    @Override
    public PostResponse getAllPosts(int pageNo, int pageSize, String sortBy, String sortDir) {
        // creazione di un oggetto Sort
        Sort sort = sortDir.equalsIgnoreCase( Sort.Direction.ASC.name() ) ? Sort.by( sortBy ).ascending()
                : Sort.by( sortBy ).descending();

        // creazione di un oggetto Pageable
        Pageable pageable = PageRequest.of( pageNo, pageSize, sort );

        Page<Post> postPageList = postRepository.findAll(pageable);

        // prendere il contenuto dal dall'oggetto Page
        List<Post> postList = postPageList.getContent();

        List<PostDto> content = postList.stream().map( post -> modelMapper.map( post, PostDto.class ) ).toList();

        PostResponse postResponse = new PostResponse();
        postResponse.setContent( content );
        postResponse.setPageNo( postPageList.getNumber() );
        postResponse.setPageSize( postPageList.getSize() );
        postResponse.setTotalElements( postPageList.getTotalElements() );
        postResponse.setTotalPages( postPageList.getTotalPages() );
        postResponse.setLast( postPageList.isLast() );

        return postResponse;
    }

    // Recupero di un Post tramite ID
    @Override
    public PostDto getPostById( Long id ) {
        Post post = postRepository.findById( id ).orElseThrow(() -> new ResourceNotFoundException("Post", "id", id));
        return modelMapper.map( post, PostDto.class );
    }

    // Aggiornamento di un Post tramite ID
    @Override
    public PostDto updatePost( PostDto postDto, Long id ) {
        // Recupero l'ENTITY dal DB tramite ID
        Post post = postRepository.findById( id ).orElseThrow(() -> new ResourceNotFoundException("Post", "id", id));

        // Recupero la Category dal DB tramite ID
        Category category = categoryRepository.findById( postDto.getCategoryId() )
                .orElseThrow(() -> new ResourceNotFoundException("Category", "id", postDto.getCategoryId()));

        post.setTitle( postDto.getTitle() );
        post.setDescription( postDto.getDescription() );
        post.setContent( postDto.getContent() );
        // Settare la Category
        post.setCategory( category );

        // Salvare l'ENTITY nel DB
        Post updatedPost = postRepository.save( post );
        return modelMapper.map( updatedPost, PostDto.class );
    }

    // Eliminazione di un Post tramite ID
    @Override
    public void deletePostById( Long id ) {
        // Recupero l'ENTITY dal DB tramite ID
        Post post = postRepository.findById( id ).orElseThrow(() -> new ResourceNotFoundException("Post", "id", id));

        // Eliminare l'ENTITY dal DB
        postRepository.delete( post );
    }

    @Override
    public List<PostDto> getAllPostsByCategoryId( Long categoryId ) {

        Category category = categoryRepository.findById( categoryId )
                .orElseThrow(() -> new ResourceNotFoundException("Category", "id", categoryId));

        List<Post> postList = postRepository.findAllByCategoryId( category.getId() );

        return postList.stream().map( post -> modelMapper.map( post, PostDto.class ) ).toList();
    }

}

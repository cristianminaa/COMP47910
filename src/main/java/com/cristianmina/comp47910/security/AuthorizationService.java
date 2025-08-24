package com.cristianmina.comp47910.security;

import com.cristianmina.comp47910.exceptions.AuthorNotFoundException;
import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Author;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.repository.AuthorRepository;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class AuthorizationService {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationService.class);
    
    private final UserRepository userRepository;
    private final AuthorRepository authorRepository;
    private final BookRepository bookRepository;
    
    public AuthorizationService(UserRepository userRepository, 
                               AuthorRepository authorRepository, 
                               BookRepository bookRepository) {
        this.userRepository = userRepository;
        this.authorRepository = authorRepository;
        this.bookRepository = bookRepository;
    }
    
    /**
     * Validates that the authenticated user has admin privileges
     */
    public void requireAdminRole(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            logger.warn("Access denied - User not authenticated");
            throw new AccessDeniedException("Authentication required");
        }
        
        boolean isAdmin = authentication.getAuthorities().stream()
            .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
            
        if (!isAdmin) {
            logger.warn("Access denied - User {} does not have ADMIN role", 
                Utilities.sanitizeLogInput(authentication.getName()));
            throw new AccessDeniedException("Admin privileges required");
        }
    }
    
    /**
     * Securely retrieves an author by ID with authorization check
     */
    public Author getAuthorWithAuthorization(Long authorId, Authentication authentication) throws AuthorNotFoundException {
        requireAdminRole(authentication);
        
        if (authorId == null || authorId <= 0) {
            logger.warn("Invalid author ID provided: {}", authorId);
            throw new IllegalArgumentException("Invalid author ID");
        }
        
        Author author = authorRepository.findById(authorId)
            .orElseThrow(() -> {
                logger.warn("Author not found with ID: {} requested by user: {}", 
                    authorId, Utilities.sanitizeLogInput(authentication.getName()));
                return new AuthorNotFoundException(authorId);
            });
            
        logger.info("Author {} (ID: {}) accessed by admin user: {}", 
            author.getFullName(), authorId, Utilities.sanitizeLogInput(authentication.getName()));
            
        return author;
    }
    
    /**
     * Securely retrieves a book by ID with authorization check
     */
    public Book getBookWithAuthorization(Long bookId, Authentication authentication) throws BookNotFoundException {
        requireAdminRole(authentication);
        
        if (bookId == null || bookId <= 0) {
            logger.warn("Invalid book ID provided: {}", bookId);
            throw new IllegalArgumentException("Invalid book ID");
        }
        
        Book book = bookRepository.findById(bookId)
            .orElseThrow(() -> {
                logger.warn("Book not found with ID: {} requested by user: {}", 
                    bookId, Utilities.sanitizeLogInput(authentication.getName()));
                return new BookNotFoundException(bookId);
            });
            
        logger.info("Book {} (ID: {}) accessed by admin user: {}", 
            book.getTitle(), bookId, Utilities.sanitizeLogInput(authentication.getName()));
            
        return book;
    }
    
    /**
     * Validates that an author can be modified by the authenticated user
     */
    public void validateAuthorModificationPermission(Long authorId, Authentication authentication) throws AuthorNotFoundException {
        requireAdminRole(authentication);
        getAuthorWithAuthorization(authorId, authentication);
        logger.info("Author modification permission granted for ID: {} to user: {}", 
            authorId, Utilities.sanitizeLogInput(authentication.getName()));
    }
    
    /**
     * Validates that a book can be modified by the authenticated user  
     */
    public void validateBookModificationPermission(Long bookId, Authentication authentication) throws BookNotFoundException {
        requireAdminRole(authentication);
        getBookWithAuthorization(bookId, authentication);
        logger.info("Book modification permission granted for ID: {} to user: {}", 
            bookId, Utilities.sanitizeLogInput(authentication.getName()));
    }
    
    /**
     * Validates that an author can be deleted by the authenticated user
     */
    public void validateAuthorDeletionPermission(Long authorId, Authentication authentication) throws AuthorNotFoundException {
        requireAdminRole(authentication);
        Author author = getAuthorWithAuthorization(authorId, authentication);
        
        // Additional business logic: Check if author has books
        if (author.getBooks() != null && !author.getBooks().isEmpty()) {
            logger.warn("Deletion denied - Author {} (ID: {}) has {} associated books", 
                author.getFullName(), authorId, author.getBooks().size());
            throw new IllegalStateException("Cannot delete author with associated books");
        }
        
        logger.info("Author deletion permission granted for ID: {} to user: {}", 
            authorId, Utilities.sanitizeLogInput(authentication.getName()));
    }
    
    /**
     * Validates that a book can be deleted by the authenticated user
     */
    public void validateBookDeletionPermission(Long bookId, Authentication authentication) throws BookNotFoundException {
        requireAdminRole(authentication);
        getBookWithAuthorization(bookId, authentication);
        logger.info("Book deletion permission granted for ID: {} to user: {}", 
            bookId, Utilities.sanitizeLogInput(authentication.getName()));
    }
    
    /**
     * Logs access attempts for security monitoring
     */
    public void logResourceAccess(String resourceType, Long resourceId, String operation, 
                                 Authentication authentication, boolean success) {
        if (success) {
            logger.info("SECURITY_AUDIT: {} {} operation on {} ID {} by user: {}", 
                success ? "SUCCESSFUL" : "FAILED", operation, resourceType, resourceId,
                Utilities.sanitizeLogInput(authentication != null ? authentication.getName() : "ANONYMOUS"));
        } else {
            logger.warn("SECURITY_AUDIT: {} {} operation on {} ID {} by user: {}", 
                success ? "SUCCESSFUL" : "FAILED", operation, resourceType, resourceId,
                Utilities.sanitizeLogInput(authentication != null ? authentication.getName() : "ANONYMOUS"));
        }
    }
}
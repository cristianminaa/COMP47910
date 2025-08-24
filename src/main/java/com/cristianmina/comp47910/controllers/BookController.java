package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.dto.BookCreateDto;
import com.cristianmina.comp47910.dto.BookUpdateDto;
import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Author;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.repository.AuthorRepository;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.repository.UserRepository;
import com.cristianmina.comp47910.security.AuthorizationService;
import com.cristianmina.comp47910.security.Utilities;
import com.cristianmina.comp47910.service.DtoConversionService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;


@Controller
public class BookController {
  private final BookRepository bookRepository;
  private final UserRepository userRepository;
  private final AuthorRepository authorRepository;
  private final AuthorizationService authorizationService;
  private final DtoConversionService dtoConversionService;
  private static final Logger logger = LoggerFactory.getLogger(BookController.class);

  public BookController(BookRepository bookRepository, UserRepository userRepository, 
                       AuthorRepository authorRepository, AuthorizationService authorizationService,
                       DtoConversionService dtoConversionService) {
    this.bookRepository = bookRepository;
    this.userRepository = userRepository;
    this.authorRepository = authorRepository;
    this.authorizationService = authorizationService;
    this.dtoConversionService = dtoConversionService;
  }

  // Show All Books
  @GetMapping({"/books"})
  public String getAllBooks(Model model) {
    List<Book> listBooks = bookRepository.findAll();
    model.addAttribute("listBooks", listBooks);
    return "books";
  }

  // Show Add Book Form
  @GetMapping("/new")
  @PreAuthorize("isAuthenticated() && hasRole('ADMIN')")
  public String showAddBookForm(Model model) {
    model.addAttribute("bookCreate", new BookCreateDto());
    model.addAttribute("listAuthors", authorRepository.findAll());
    return "addBook";
  }

  // Create a new Book
  @PostMapping("/books")
  @PreAuthorize("isAuthenticated() && hasRole('ADMIN')")
  @Transactional(rollbackFor = Exception.class)
  public String newBook(@Valid @ModelAttribute("bookCreate") BookCreateDto bookCreateDto,
                        BindingResult result,
                        Authentication authentication,
                        Model model) {
    
    if (result.hasErrors()) {
      model.addAttribute("listAuthors", authorRepository.findAll());
      return "addBook";
    }

    Book book = bookCreateDto.toEntity();

    if (bookCreateDto.getAuthorIds() != null && !bookCreateDto.getAuthorIds().isEmpty()) {
      List<Author> authors = authorRepository.findAllById(bookCreateDto.getAuthorIds());
      book.setAuthors(authors);
      for (Author author : authors) {
        if (!author.getBooks().contains(book)) {
          author.getBooks().add(book);
        }
      }
    } else {
      book.setAuthors(new ArrayList<>());
    }
    
    bookRepository.save(book);
    logger.info("New book added: {} ID: {} by user: {}", book.getTitle(), book.getId(), Utilities.sanitizeLogInput(authentication.getName()));
    return "redirect:/books";
  }

  // Get a Single Book
  @PreAuthorize("isAuthenticated() && hasRole('ADMIN')")
  @GetMapping("/books/{id}")
  public String getBookById(@PathVariable(value = "id") Long bookId, Model model, 
                           Authentication authentication) throws BookNotFoundException {
    // Secure authorization check with IDOR protection
    Book book = authorizationService.getBookWithAuthorization(bookId, authentication);
    authorizationService.logResourceAccess("Book", bookId, "READ", authentication, true);
    
    BookUpdateDto bookUpdateDto = BookUpdateDto.fromEntity(book);
    
    model.addAttribute("bookUpdate", bookUpdateDto);
    model.addAttribute("authorsOfBook", book.getAuthors());
    model.addAttribute("listAuthors", authorRepository.findAll());
    return "editBook";
  }

  // Update an Existing Book
  @PreAuthorize("isAuthenticated() && hasRole('ADMIN')")
  @PutMapping("/books")
  @Transactional(rollbackFor = Exception.class)
  public String updateBook(@Valid @ModelAttribute("bookUpdate") BookUpdateDto bookUpdateDto,
                           BindingResult result,
                           Authentication authentication,
                           Model model) throws BookNotFoundException {

    // Early authorization check with IDOR protection
    authorizationService.validateBookModificationPermission(bookUpdateDto.getId(), authentication);

    if (result.hasErrors()) {
      Book book = authorizationService.getBookWithAuthorization(bookUpdateDto.getId(), authentication);
      model.addAttribute("authorsOfBook", book.getAuthors());
      model.addAttribute("listAuthors", authorRepository.findAll());
      authorizationService.logResourceAccess("Book", bookUpdateDto.getId(), "UPDATE_VALIDATION_FAILED", authentication, false);
      return "editBook";
    }

    // Secure retrieval with authorization
    Book existingBook = authorizationService.getBookWithAuthorization(bookUpdateDto.getId(), authentication);

    // Update fields from DTO data
    bookUpdateDto.updateEntity(existingBook);

    // Handle authors relationship
    if (bookUpdateDto.getAuthorIds() != null && !bookUpdateDto.getAuthorIds().isEmpty()) {
      List<Author> authors = authorRepository.findAllById(bookUpdateDto.getAuthorIds());
      existingBook.setAuthors(authors);
      for (Author author : authors) {
        if (!author.getBooks().contains(existingBook)) {
          author.getBooks().add(existingBook);
        }
      }
    } else {
      existingBook.setAuthors(new ArrayList<>());
      for (Author author : authorRepository.findAll()) {
        author.getBooks().removeIf(authoredBook -> authoredBook.getId().equals(existingBook.getId()));
        authorRepository.save(author);
      }
    }

    logger.info("Book updated: {} ID: {} by user: {}", existingBook.getTitle(), existingBook.getId(), Utilities.sanitizeLogInput(authentication.getName()));
    authorizationService.logResourceAccess("Book", bookUpdateDto.getId(), "UPDATE", authentication, true);
    bookRepository.save(existingBook);
    return "redirect:/books";
  }

  // Delete a Book
  @PreAuthorize("isAuthenticated() && hasRole('ADMIN')")
  @DeleteMapping("/books/delete/{id}")
  @Transactional(rollbackFor = Exception.class)
  public String deleteBook(@PathVariable(value = "id") Long bookId,
                           Authentication authentication) throws BookNotFoundException {
    // Secure authorization check with IDOR protection
    authorizationService.validateBookDeletionPermission(bookId, authentication);
    
    // Secure retrieval after authorization
    Book book = authorizationService.getBookWithAuthorization(bookId, authentication);
    
    userRepository.findAll().forEach(user -> {
      boolean removed = user.getCart().keySet().removeIf(deletedBook -> deletedBook.getId().equals(bookId));
      if (removed) {
        userRepository.save(user);
      }
    });
    authorRepository.findAll().forEach(author -> {
      boolean removed = author.getBooks().removeIf(deletedBook -> deletedBook.getId().equals(bookId));
      if (removed) {
        authorRepository.save(author);
      }
    });
    logger.info("Book deleted: {} ID: {} by user: {}", book.getTitle(), book.getId(), Utilities.sanitizeLogInput(authentication.getName()));
    authorizationService.logResourceAccess("Book", bookId, "DELETE", authentication, true);
    bookRepository.delete(book);
    return "redirect:/books";
  }

}

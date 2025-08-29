package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.dto.AuthorCreateDto;
import com.cristianmina.comp47910.dto.AuthorUpdateDto;
import com.cristianmina.comp47910.exceptions.AuthorNotFoundException;
import com.cristianmina.comp47910.model.Author;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.repository.AuthorRepository;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.security.AuthorizationService;
import com.cristianmina.comp47910.security.Utilities;
import com.cristianmina.comp47910.service.DtoConversionService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Positive;
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
@PreAuthorize("hasRole('ADMIN')")
public class AuthorController {
  private final AuthorRepository authorRepository;
  private final BookRepository bookRepository;
  private final AuthorizationService authorizationService;
  private final DtoConversionService dtoConversionService;
  private static final Logger logger = LoggerFactory.getLogger(AuthorController.class);

  public AuthorController(AuthorRepository authorRepository, BookRepository bookRepository,
                          AuthorizationService authorizationService, DtoConversionService dtoConversionService) {
    this.authorRepository = authorRepository;
    this.bookRepository = bookRepository;
    this.authorizationService = authorizationService;
    this.dtoConversionService = dtoConversionService;
  }

  // Get All Authors
  @GetMapping("/authors")
  @PreAuthorize("permitAll()")
  public String getAllAuthors(Model model) {
    List<Author> listAuthors = authorRepository.findAll();
    model.addAttribute("listAuthors", listAuthors);
    return "authors";
  }

  // Show Add Author Form
  @PreAuthorize("isAuthenticated()")
  @RequestMapping("/addAuthor")
  public String showAddAuthorForm(Model model) {
    model.addAttribute("authorCreate", new AuthorCreateDto());
    model.addAttribute("listBooks", bookRepository.findAll());
    return "addAuthor";
  }

  // Create a New Author
  @PreAuthorize("isAuthenticated()")
  @PostMapping("/addAuthor")
  @Transactional(rollbackFor = Exception.class)
  public String newAuthor(@Valid @ModelAttribute("authorCreate") AuthorCreateDto authorCreateDto,
                          BindingResult result,
                          Authentication authentication,
                          Model model) {

    if (result.hasErrors()) {
      model.addAttribute("listBooks", bookRepository.findAll());
      return "addAuthor";
    }

    Author author = authorCreateDto.toEntity();

    if (authorCreateDto.getBookIds() != null && !authorCreateDto.getBookIds().isEmpty()) {
      List<Book> books = bookRepository.findAllById(authorCreateDto.getBookIds());
      author.setBooks(books);
      for (Book book : books) {
        if (!book.getAuthors().contains(author)) {
          book.addAuthor(author);
        }
      }
    } else {
      author.setBooks(new ArrayList<>());
    }

    logger.info("New author added: {} by user: {}", author.getId(), Utilities.sanitizeLogInput(authentication.getName()));
    authorRepository.save(author);
    return "redirect:/authors";
  }

  // Get a Single Author
  @PreAuthorize("isAuthenticated()")
  @GetMapping("/authors/{id}")
  public String getAuthorById(@PathVariable(value = "id") @Positive Long authorId,
                              Model model,
                              Authentication authentication) throws AuthorNotFoundException {
    // Secure authorization check with IDOR protection
    Author author = authorizationService.getAuthorWithAuthorization(authorId, authentication);
    authorizationService.logResourceAccess("Author", authorId, "READ", authentication, true);

    AuthorUpdateDto authorUpdateDto = dtoConversionService.convertAuthorEntityToUpdateDto(author);

    model.addAttribute("authorUpdate", authorUpdateDto);
    model.addAttribute("authoredBooks", author.getBooks());
    model.addAttribute("listBooks", bookRepository.findAll());
    return "editAuthor";
  }

  // Update an Existing Author
  @PreAuthorize("isAuthenticated()")
  @PutMapping("/editAuthor")
  @Transactional(rollbackFor = Exception.class)
  public String updateAuthor(@Valid @ModelAttribute("authorUpdate") AuthorUpdateDto authorUpdateDto,
                             BindingResult result,
                             Authentication authentication,
                             Model model) throws AuthorNotFoundException {

    // Early authorization check with IDOR protection
    authorizationService.validateAuthorModificationPermission(authorUpdateDto.getId(), authentication);

    if (result.hasErrors()) {
      Author author = authorizationService.getAuthorWithAuthorization(authorUpdateDto.getId(), authentication);
      model.addAttribute("authoredBooks", author.getBooks());
      model.addAttribute("listBooks", bookRepository.findAll());
      authorizationService.logResourceAccess("Author", authorUpdateDto.getId(), "UPDATE_VALIDATION_FAILED", authentication, false);
      return "editAuthor";
    }

    // Secure retrieval with authorization 
    Author author = authorizationService.getAuthorWithAuthorization(authorUpdateDto.getId(), authentication);

    authorUpdateDto.updateEntity(author);

    if (authorUpdateDto.getBookIds() != null && !authorUpdateDto.getBookIds().isEmpty()) {
      List<Book> books = bookRepository.findAllById(authorUpdateDto.getBookIds());
      author.setBooks(books);
      for (Book book : books) {
        if (!book.getAuthors().contains(author)) {
          book.addAuthor(author);
        }
      }
    } else {
      author.setBooks(new ArrayList<>());
      for (Book book : bookRepository.findAll()) {
        book.getAuthors().removeIf(authorOfBook -> authorOfBook.getId().equals(author.getId()));
        bookRepository.save(book);
      }
    }

    logger.info("Author updated: {} by user: {}", author.getFullName(), Utilities.sanitizeLogInput(authentication.getName()));
    authorizationService.logResourceAccess("Author", authorUpdateDto.getId(), "UPDATE", authentication, true);
    authorRepository.save(author);
    return "redirect:/authors";
  }

  // Delete an Author
  @PreAuthorize("isAuthenticated()")
  @DeleteMapping("/authors/{id}")
  @Transactional(rollbackFor = Exception.class)
  public String deleteAuthor(@PathVariable(value = "id") @Positive Long authorId,
                             Authentication authentication) throws AuthorNotFoundException {
    // Secure authorization check with business logic validation
    authorizationService.validateAuthorDeletionPermission(authorId, authentication);

    // Secure retrieval after authorization
    Author author = authorizationService.getAuthorWithAuthorization(authorId, authentication);

    bookRepository.findAll().forEach(book -> {
      boolean removed = book.getAuthors().removeIf(deletedAuthor -> deletedAuthor.getId().equals(authorId));
      if (removed) {
        bookRepository.save(book);
      }
    });

    logger.info("Author deleted: {} by user: {}", author.getFullName(), Utilities.sanitizeLogInput(authentication.getName()));
    authorizationService.logResourceAccess("Author", authorId, "DELETE", authentication, true);
    authorRepository.delete(author);
    return "redirect:/authors";
  }

}

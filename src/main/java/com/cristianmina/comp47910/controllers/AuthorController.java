package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.exceptions.AuthorNotFoundException;
import com.cristianmina.comp47910.model.Author;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.repository.AuthorRepository;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.security.Utilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@Controller
@PreAuthorize("hasRole('ADMIN')")
public class AuthorController {
  private final AuthorRepository authorRepository;
  private final BookRepository bookRepository;
  private static final Logger logger = LoggerFactory.getLogger(AuthorController.class);

  public AuthorController(AuthorRepository authorRepository, BookRepository bookRepository) {
    this.authorRepository = authorRepository;
    this.bookRepository = bookRepository;
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
    model.addAttribute("author", new Author());
    model.addAttribute("listBooks", bookRepository.findAll());
    return "addAuthor";
  }

  // Create a New Author
  @PreAuthorize("isAuthenticated()")
  @PostMapping("/addAuthor")
  @Transactional(rollbackFor = Exception.class)
  public String newAuthor(@ModelAttribute("author") Author author,
                          @RequestParam(value = "books", required = false) List<Long> bookIds,
                          Authentication authentication) {
    if (bookIds != null && !bookIds.isEmpty()) {
      author.setBooks(bookRepository.findAllById(bookIds));
      for (Book book : author.getBooks()) {
        if (!book.getAuthors().contains(author)) {
          book.addAuthor(author);
        }
      }
    } else {
      author.setBooks(new ArrayList<>());
    }
    logger.info("New author added: {} by user: {}", author.getFullName(), Utilities.sanitizeLogInput(authentication.getName()));
    authorRepository.save(author);
    return "redirect:/authors";
  }

  // Get a Single Author
  @PreAuthorize("isAuthenticated()")
  @GetMapping("/authors/{id}")
  public String getAuthorById(@PathVariable(value = "id") Long authorId,
                              Model model) throws AuthorNotFoundException {
    Author author = authorRepository.findById(authorId).orElseThrow(() -> new AuthorNotFoundException(authorId));
    model.addAttribute("author", author);
    model.addAttribute("authoredBooks", author.getBooks());
    model.addAttribute("listBooks", bookRepository.findAll());
    return "editAuthor";
  }

  // Update an Existing Author
  @PreAuthorize("isAuthenticated()")
  @PutMapping("/editAuthor")
  @Transactional(rollbackFor = Exception.class)
  public String updateAuthor(@ModelAttribute("author") Author author,
                             @RequestParam(value = "books", required = false) List<Long> bookIds,
                             Authentication authentication) {
    if (bookIds != null && !bookIds.isEmpty()) {
      author.setBooks(bookRepository.findAllById(bookIds));
      for (Book book : author.getBooks()) {
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
    authorRepository.save(author);
    return "redirect:/authors";
  }

  // Delete an Author
  @PreAuthorize("isAuthenticated()")
  @DeleteMapping("/authors/{id}")
  @Transactional(rollbackFor = Exception.class)
  public String deleteAuthor(@PathVariable(value = "id") Long authorId,
                             Authentication authentication) throws AuthorNotFoundException {
    bookRepository.findAll().forEach(book -> {
      boolean removed = book.getAuthors().removeIf(deletedAuthor -> deletedAuthor.getId().equals(authorId));
      if (removed) {
        bookRepository.save(book);
      }
    });
    Author author = authorRepository.findById(authorId).orElseThrow(() -> new AuthorNotFoundException(authorId));
    logger.info("Author deleted: {} by user: {}", author.getFullName(), Utilities.sanitizeLogInput(authentication.getName()));
    authorRepository.delete(author);
    return "redirect:/authors";
  }

}

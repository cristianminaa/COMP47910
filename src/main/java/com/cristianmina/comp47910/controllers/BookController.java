package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Author;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.repository.AuthorRepository;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;


@Controller
public class BookController {
  @Autowired
  private BookRepository bookRepository;
  @Autowired
  private UserRepository userRepository;
  @Autowired
  private AuthorRepository authorRepository;
  private static final Logger logger = LoggerFactory.getLogger(BookController.class);

  // Show All Books
  @GetMapping({"/books"})
  public String getAllBooks(Model model) {
    List<Book> listBooks = bookRepository.findAll();
    model.addAttribute("listBooks", listBooks);
    return "books";
  }

  // Show Add Book Form
  @GetMapping("/new")
  @PreAuthorize("isAuthenticated() and hasRole('ADMIN')")
  public String showAddBookForm(Model model) {
    model.addAttribute("book", new Book());
    model.addAttribute("listAuthors", authorRepository.findAll());
    return "addBook";
  }

  // Create a new Book
  @PostMapping("/books")
  @PreAuthorize("isAuthenticated() and hasRole('ADMIN')")
  @Transactional(rollbackFor = Exception.class)
  public String newBook(@ModelAttribute("book") Book book,
                        @RequestParam(value = "authors", required = false) List<Long> authors,
                        Authentication authentication,
                        Model model) {
    if (authors != null && !authors.isEmpty()) {
      book.setAuthors(authorRepository.findAllById(authors));
      for (Author author : book.getAuthors()) {
        if (!author.getBooks().contains(book)) {
          author.getBooks().add(book);
        }
      }
    } else {
      book.setAuthors(new ArrayList<>());
    }
    bookRepository.save(book);
    logger.info("New book added: {} ID: {} by user: {}", book.getTitle(), book.getId(), authentication.getName());
    model.addAttribute("book", book);
    return "redirect:/books";
  }

  // Get a Single Book
  @PreAuthorize("isAuthenticated() and hasRole('ADMIN')")
  @GetMapping("/books/{id}")
  public String getBookById(@PathVariable(value = "id") Long bookId, Model model) throws BookNotFoundException {
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
    model.addAttribute("book", book);
    model.addAttribute("authorsOfBook", book.getAuthors());
    model.addAttribute("listAuthors", authorRepository.findAll());
    return "editBook";
  }

  // Update an Existing Book
  @PreAuthorize("isAuthenticated() and hasRole('ADMIN')")
  @PutMapping("/books")
  @Transactional(rollbackFor = Exception.class)
  public String updateBook(@ModelAttribute("book") Book book,
                           @RequestParam(value = "authors", required = false) List<Long> authors,
                           Authentication authentication) throws BookNotFoundException {
    
    // Fetch the existing book with proper version handling
    Book existingBook = bookRepository.findById(book.getId())
            .orElseThrow(() -> new BookNotFoundException(book.getId()));
    
    // Update fields from form data
    existingBook.setTitle(book.getTitle());
    existingBook.setPrice(book.getPrice());
    existingBook.setYear(book.getYear());
    existingBook.setNumberOfCopies(book.getNumberOfCopies());
    
    // Handle authors relationship
    if (authors != null && !authors.isEmpty()) {
      existingBook.setAuthors(authorRepository.findAllById(authors));
      for (Author author : existingBook.getAuthors()) {
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
    
    logger.info("Book updated: {} ID: {} by user: {}", existingBook.getTitle(), existingBook.getId(), authentication.getName());
    bookRepository.save(existingBook);
    return "redirect:/books";
  }

  // Delete a Book
  @PreAuthorize("isAuthenticated() and hasRole('ADMIN')")
  @DeleteMapping("/books/delete/{id}")
  @Transactional(rollbackFor = Exception.class)
  public String deleteBook(@PathVariable(value = "id") Long bookId,
                           Authentication authentication) throws BookNotFoundException {
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
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
    logger.info("Book deleted: {} ID: {} by user: {}", book.getTitle(), book.getId(), authentication.getName());
    bookRepository.delete(book);
    return "redirect:/books";
  }

}

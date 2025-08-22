package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.exceptions.AuthorNotFoundException;
import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Author;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.model.UserRole;
import com.cristianmina.comp47910.repository.AuthorRepository;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
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

  // Show All Books
  @GetMapping({"/books"})
  public String getAllBooks(Model model, HttpSession session) {
    List<Book> listBooks = bookRepository.findAll();
    model.addAttribute("listBooks", listBooks);
    return "books";
  }

  // Show Add Book Form
  @GetMapping("/new")
  public String showAddBookForm(Model model, HttpSession session) {
    User user = (User) session.getAttribute("user");
    if (user == null || user.getRole() != UserRole.ADMIN) {
      return "redirect:/";
    }
    model.addAttribute("book", new Book());
    model.addAttribute("listAuthors", authorRepository.findAll());
    return "addBook";
  }

  // Create a new Book
  @PostMapping("/books")
  @Transactional(rollbackFor = Exception.class)
  public String newBook(@ModelAttribute("book") Book book, @RequestParam(value = "authors", required = false) List<Long> authors, Model model, HttpSession session) {
    User user = (User) session.getAttribute("user");
    if (user == null || user.getRole() != UserRole.ADMIN) {
      return "redirect:/";
    }
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
    model.addAttribute("book", book);
    return "redirect:/books";
  }

  // Get a Single Book
  @GetMapping("/books/{id}")
  public String getBookById(@PathVariable(value = "id") Long bookId, Model model, HttpSession session) throws BookNotFoundException {
    User user = (User) session.getAttribute("user");
    if (user == null || user.getRole() != UserRole.ADMIN) {
      return "redirect:/";
    }
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
    model.addAttribute("book", book);
    model.addAttribute("authorsOfBook", book.getAuthors());
    model.addAttribute("listAuthors", authorRepository.findAll());
    return "editBook";
  }

  // Update an Existing Book
  @PutMapping("/books")
  @Transactional(rollbackFor = Exception.class)
  public String updateBook(@ModelAttribute("book") Book book,
                           @RequestParam(value = "authors", required = false) List<Long> authors,
                           Model model,
                           HttpSession session) throws BookNotFoundException {
    User user = (User) session.getAttribute("user");
    if (user == null || user.getRole() != UserRole.ADMIN) {
      return "redirect:/";
    }
    if (authors != null && !authors.isEmpty()) {
      book.setAuthors(authorRepository.findAllById(authors));
      for (Author author : book.getAuthors()) {
        if (!author.getBooks().contains(book)) {
          author.getBooks().add(book);
        }
      }
    } else {
      book.setAuthors(new ArrayList<>());
      for (Author author : authorRepository.findAll()) {
        author.getBooks().removeIf(authoredBook -> authoredBook.getId().equals(book.getId()));
        authorRepository.save(author);
      }
    }
    bookRepository.save(book);
    return "redirect:/books";
  }

  // Delete a Book
  @DeleteMapping("/books/delete/{id}")
  @Transactional(rollbackFor = Exception.class)
  public String deleteBook(@PathVariable(value = "id") Long bookId,
                           Model model,
                           HttpSession session) throws BookNotFoundException {
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
    bookRepository.delete(book);
    return "redirect:/books";
  }

}

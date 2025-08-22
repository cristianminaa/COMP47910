package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.exceptions.AuthorNotFoundException;
import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Author;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.model.UserRole;
import com.cristianmina.comp47910.repository.AuthorRepository;
import com.cristianmina.comp47910.repository.BookRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@Controller
public class AuthorController {
  @Autowired
  private AuthorRepository authorRepository;
  @Autowired
  private BookRepository bookRepository;

  // Get All Authors
  @GetMapping( "/authors")
  public String getAllAuthors(Model model) {
    List<Author> listAuthors = authorRepository.findAll();
    model.addAttribute("listAuthors", listAuthors);
    return "authors";
  }

  // Show Add Author Form
  @RequestMapping("/addAuthor")
  public String showAddAuthorForm(Model model,
                                  HttpSession session) {
    User user = (User) session.getAttribute("user");
    if (user == null || user.getRole() != UserRole.ADMIN) {
      return "redirect:/";
    }
    model.addAttribute("author", new Author());
    model.addAttribute("listBooks", bookRepository.findAll());
    return "addAuthor";
  }

  // Create a New Author
  @PostMapping("/authors")
  @Transactional(rollbackFor = Exception.class)
  public String newAuthor(@ModelAttribute("author") Author author,
                          @RequestParam(value = "books", required = false) List<Long> bookIds,
                          Model model,
                          HttpSession session) {
    User user = (User) session.getAttribute("user");
    if (user == null || user.getRole() != UserRole.ADMIN) {
      return "redirect:/";
    }
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
    authorRepository.save(author);
    return "redirect:/authors";
  }

  // Get a Single Author
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
  @PutMapping("/authors")
  @Transactional(rollbackFor = Exception.class)
  public String updateAuthor(@ModelAttribute("author") Author author,
                             @RequestParam(value = "books", required = false) List<Long> bookIds,
                             Model model,
                             HttpSession session) {
    User user = (User) session.getAttribute("user");
    if (user == null || user.getRole() != UserRole.ADMIN) {
      return "redirect:/";
    }
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
    authorRepository.save(author);
    return "redirect:/authors";
  }

  // Delete an Author
  @DeleteMapping("/authors/{id}")
  @Transactional(rollbackFor = Exception.class)
  public String deleteAuthor(@PathVariable(value = "id") Long authorId,
                             Model model,
                             HttpSession session) throws AuthorNotFoundException {
    User user = (User) session.getAttribute("user");
    if (user == null || user.getRole() != UserRole.ADMIN) {
      return "redirect:/";
    }
    bookRepository.findAll().forEach(book -> {
      boolean removed = book.getAuthors().removeIf(deletedAuthor -> deletedAuthor.getId().equals(authorId));
      if (removed) {
        bookRepository.save(book);
      }
    });
    Author author = authorRepository.findById(authorId).orElseThrow(() -> new AuthorNotFoundException(authorId));
    authorRepository.delete(author);
    return "redirect:/authors";
  }

}

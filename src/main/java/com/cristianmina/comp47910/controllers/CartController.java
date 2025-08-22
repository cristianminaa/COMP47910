package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.repository.UserRepository;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
public class CartController {

  @Autowired
  private BookRepository bookRepository;
  @Autowired
  private UserRepository userRepository;

  // Show Cart
  @PreAuthorize("hasRole('USER')")
  @GetMapping("/cart")
  public String showCart(Model model,
                         Authentication authentication) {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Map<Book, Integer> booksInCart = user.getCart();
    model.addAttribute("booksInCart", booksInCart);
    model.addAttribute("user", user);
    return "cart";
  }

  // Add Book to Cart
  @PreAuthorize("hasRole('USER')")
  @PostMapping("/cart/{id}")
  public String addToCart(@PathVariable(value = "id") Long bookId,
                          @RequestParam(defaultValue = "1") @Min(1) @Max(99) int quantity,
                          Authentication authentication) throws BookNotFoundException {
    System.out.println("Adding to cart - Book ID: " + bookId + ", Quantity: " + quantity + ", User: " + authentication.getName());
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    System.out.println("Found user: " + user.getUsername());
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
    System.out.println("Found book: " + book.getTitle());
    user.addToCart(book, quantity);
    userRepository.save(user);
    System.out.println("Successfully added to cart");
    return "redirect:/cart";
  }

  // Update Book Quantity in Cart
  @PreAuthorize("hasRole('USER')")
  @PutMapping("/cart/update/{id}")
  public String updateQuantityInCart(@PathVariable(value = "id") Long bookId,
                                     @RequestParam(defaultValue = "1") int quantity,
                                     Authentication authentication) throws BookNotFoundException {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
    user.setQuantityInCart(book, quantity);
    userRepository.save(user);
    return "redirect:/cart";
  }

  // Remove Book from Cart
  @PreAuthorize("hasRole('USER')")
  @DeleteMapping("/cart/delete/{id}")
  public String deleteFromCart(@PathVariable(value = "id") Long bookId,
                               Authentication authentication) throws BookNotFoundException {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
    user.removeFromCart(book);
    userRepository.save(user);
    return "redirect:/cart";
  }
}

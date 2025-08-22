package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Admin;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
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

  // Show Add Book Form
  @GetMapping("/cart")
  public String showCart(Model model,
                         HttpSession session) {
    if (session.getAttribute("user") == null || session.getAttribute("user") instanceof Admin) {
      return "redirect:/";
    }
    User sessionUser = (User) session.getAttribute("user");
    User user = userRepository.findByUsername(sessionUser.getUsername()).orElseThrow();
    Map<Book, Integer> booksInCart = user.getCart();
    model.addAttribute("booksInCart", booksInCart);
    model.addAttribute("user", user);
    return "cart";
  }

  // Add Book to Cart
  @PostMapping("/cart/{id}")
  public String addToCart(@PathVariable(value = "id") Long bookId,
                          @RequestParam(defaultValue = "1") int quantity,
                          HttpSession session) throws BookNotFoundException {
    if (session.getAttribute("user") == null || session.getAttribute("user") instanceof Admin) {
      return "redirect:/";
    }
    User sessionUser = (User) session.getAttribute("user");
    User user = userRepository.findByUsername(sessionUser.getUsername()).orElseThrow();
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
    user.addToCart(book, quantity);
    userRepository.save(user);
    return "redirect:/cart";
  }

  // Update Book Quantity in Cart
  @PutMapping("/cart/update/{id}")
  public String updateQuantityInCart(@PathVariable(value = "id") Long bookId,
                          @RequestParam(defaultValue = "1") int quantity,
                          HttpSession session) throws BookNotFoundException {
    if (session.getAttribute("user") == null || session.getAttribute("user") instanceof Admin) {
      return "redirect:/";
    }
    User sessionUser = (User) session.getAttribute("user");
    User user = userRepository.findByUsername(sessionUser.getUsername()).orElseThrow();
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
    user.setQuantityInCart(book, quantity);
    userRepository.save(user);
    return "redirect:/cart";
  }

  // Remove Book from Cart
  @DeleteMapping("/cart/delete/{id}")
  public String deleteFromCart(@PathVariable(value = "id") Long bookId,
                               Model model,
                               HttpSession session) throws BookNotFoundException {
    if (session.getAttribute("user") == null || session.getAttribute("user") instanceof Admin) {
      return "redirect:/";
    }
    User sessionUser = (User) session.getAttribute("user");
    User user = userRepository.findByUsername(sessionUser.getUsername()).orElseThrow();
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
    user.removeFromCart(book);
    userRepository.save(user);
    return "redirect:/cart";
  }
}

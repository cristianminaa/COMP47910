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
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Map;

@Controller
public class CheckoutController {

  @Autowired
  private BookRepository bookRepository;
  @Autowired
  private UserRepository userRepository;

  @GetMapping("/checkout")
  public String showCheckout(Model model,
                             HttpSession session) {
    if (session.getAttribute("user") == null || session.getAttribute("user") instanceof Admin) {
      return "redirect:/";
    }
    User sessionUser = (User) session.getAttribute("user");
    User user = userRepository.findByUsername(sessionUser.getUsername()).orElseThrow();
    Double totalPrice = user.getCart().entrySet().stream()
            .mapToDouble(entry -> entry.getKey().getPrice() * entry.getValue())
            .sum();
    Map<Book, Integer> booksInCart = user.getCart();
    model.addAttribute("user", user);
    model.addAttribute("booksInCart", booksInCart);
    model.addAttribute("totalPrice", totalPrice);
    return "checkout";
  }

  @PostMapping("/checkout")
  @Transactional(rollbackFor = Exception.class)
  public String placeOrder(Model model, HttpSession session) throws BookNotFoundException {
    if (session.getAttribute("user") == null || session.getAttribute("user") instanceof Admin) {
      return "redirect:/";
    }
    User sessionUser = (User) session.getAttribute("user");
    User user = userRepository.findByUsername(sessionUser.getUsername()).orElseThrow();
    Map<Book, Integer> booksInCart = user.getCart();

    for (Map.Entry<Book, Integer> entry : booksInCart.entrySet()) {
      Book book = bookRepository.findById(entry.getKey().getId())
              .orElseThrow(() -> new BookNotFoundException(entry.getKey().getId()));
      int newStock = book.getNumberOfCopies() - entry.getValue();
      if (newStock < 0) {
        throw new IllegalStateException("Not enough copies for book: " + book.getTitle());
      }
      book.setNumberOfCopies(newStock);
      bookRepository.save(book);
    }

    user.clearCart();
    userRepository.save(user);
    return "redirect:/orderConfirmation";
  }

  @GetMapping("/orderConfirmation")
  public String confirmOrder(Model model,
                             HttpSession session) {
    if (session.getAttribute("user") == null || session.getAttribute("user") instanceof Admin) {
      return "redirect:/";
    }
    User sessionUser = (User) session.getAttribute("user");
    User user = userRepository.findByUsername(sessionUser.getUsername()).orElseThrow();
    model.addAttribute("user", user);
    model.addAttribute("orderId", System.currentTimeMillis()); // Simulating an order ID
    return "orderConfirmation";
  }
}

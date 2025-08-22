package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Map;
import java.util.UUID;

@Controller
public class CheckoutController {

  @Autowired
  private BookRepository bookRepository;
  @Autowired
  private UserRepository userRepository;

  @PreAuthorize("hasRole('USER')")
  @GetMapping("/checkout")
  public String showCheckout(Model model,
                             Authentication authentication) {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Double totalPrice = user.getCart().entrySet().stream()
            .mapToDouble(entry -> {
              Book currentBook = bookRepository.findById(entry.getKey().getId()).orElse(null);
              if (currentBook == null) return 0;
              return currentBook.getPrice() * entry.getValue();
            })
            .sum();
    Map<Book, Integer> booksInCart = user.getCart();
    model.addAttribute("user", user);
    model.addAttribute("booksInCart", booksInCart);
    model.addAttribute("totalPrice", totalPrice);
    return "checkout";
  }

  @PreAuthorize("hasRole('USER')")
  @PostMapping("/checkout")
  @Transactional(rollbackFor = Exception.class)
  public String placeOrder(Authentication authentication) throws BookNotFoundException {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Map<Book, Integer> booksInCart = user.getCart();

    for (Map.Entry<Book, Integer> entry : booksInCart.entrySet()) {
      Book book = bookRepository.findByIdForUpdate(entry.getKey().getId())
              .orElseThrow(() -> new BookNotFoundException(entry.getKey().getId()));
      synchronized (book) {
        int newStock = book.getNumberOfCopies() - entry.getValue();
        if (newStock < 0) {
          throw new IllegalStateException("Not enough copies for book: " + book.getTitle());
        }
        book.setNumberOfCopies(newStock);
        bookRepository.save(book);
      }
    }

    user.clearCart();
    userRepository.save(user);
    return "redirect:/orderConfirmation";
  }

  @PreAuthorize("hasRole('USER')")
  @GetMapping("/orderConfirmation")
  public String confirmOrder(Model model,
                             Authentication authentication) {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    model.addAttribute("user", user);
    model.addAttribute("orderId", UUID.randomUUID().toString());
    return "orderConfirmation";
  }
}

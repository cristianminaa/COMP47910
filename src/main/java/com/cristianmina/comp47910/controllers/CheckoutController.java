package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.model.User;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;
import java.util.UUID;

@Controller
public class CheckoutController {

  @Autowired
  private BookRepository bookRepository;
  @Autowired
  private UserRepository userRepository;
  private static final Logger logger = LoggerFactory.getLogger(CheckoutController.class);

  @PreAuthorize("hasRole('USER')")
  @PostMapping("/checkout")
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
  @PostMapping("/placeOrder")
  @Transactional(rollbackFor = Exception.class)
  public String placeOrder(Authentication authentication) throws BookNotFoundException {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Map<Book, Integer> booksInCart = user.getCart();
    
    // Validate cart is not empty
    if (booksInCart == null || booksInCart.isEmpty()) {
      throw new IllegalStateException("Cannot checkout with empty cart");
    }
    
    String orderId = UUID.randomUUID().toString();

    // Calculate total price and log order details
    double totalPrice = 0.0;
    StringBuilder orderDetails = new StringBuilder();
    orderDetails.append("ORDER PLACED - Order ID: ").append(orderId)
              .append(", User: ").append(user.getUsername())
              .append(" (ID: ").append(user.getId()).append(")")
              .append("\nORDER ITEMS:");

    for (Map.Entry<Book, Integer> entry : booksInCart.entrySet()) {
      Book book = bookRepository.findByIdForUpdate(entry.getKey().getId())
              .orElseThrow(() -> new BookNotFoundException(entry.getKey().getId()));
      
      int quantity = entry.getValue();
      double itemTotal = book.getPrice() * quantity;
      totalPrice += itemTotal;
      
      // Log individual item details
      orderDetails.append("\n  - Book: \"").append(book.getTitle()).append("\"")
                 .append(", Book ID: ").append(book.getId())
                 .append(", Unit Price: $").append(String.format("%.2f", book.getPrice()))
                 .append(", Quantity: ").append(quantity)
                 .append(", Item Total: $").append(String.format("%.2f", itemTotal));
      
      // Optimistic locking handles concurrency automatically
      int newStock = book.getNumberOfCopies() - quantity;
      if (newStock < 0) {
        logger.error("ORDER FAILED - Order ID: {}, Insufficient stock for book: {} (ID: {}), Requested: {}, Available: {}", 
                    orderId, book.getTitle(), book.getId(), quantity, book.getNumberOfCopies());
        throw new IllegalStateException("Not enough copies for book: " + book.getTitle());
      }
      book.setNumberOfCopies(newStock);
      bookRepository.save(book); // Will throw OptimisticLockingFailureException if version conflicts
    }
    
    // Log final order summary
    orderDetails.append("\nORDER TOTAL: $").append(String.format("%.2f", totalPrice));
    logger.info(orderDetails.toString());

    user.clearCart();
    userRepository.save(user);
    
    logger.info("ORDER COMPLETED - Order ID: {}, User: {}, Total Amount: ${}", 
               orderId, user.getUsername(), String.format("%.2f", totalPrice));
    
    return "redirect:/orderConfirmation?orderId=" + orderId;
  }

  @PreAuthorize("hasRole('USER')")
  @GetMapping("/orderConfirmation")
  public String confirmOrder(@RequestParam(required = false) String orderId,
                             Model model,
                             Authentication authentication) {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    model.addAttribute("user", user);
    model.addAttribute("orderId", orderId != null ? orderId : "N/A");
    return "orderConfirmation";
  }
}

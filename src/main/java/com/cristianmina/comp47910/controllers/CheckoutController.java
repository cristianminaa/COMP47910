package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.repository.UserRepository;
import com.cristianmina.comp47910.security.RateLimitingService;
import com.cristianmina.comp47910.security.Utilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

@Controller
public class CheckoutController {

  private final BookRepository bookRepository;
  private final UserRepository userRepository;
  private final RateLimitingService rateLimitingService;
  private static final Logger logger = LoggerFactory.getLogger(CheckoutController.class);

  public CheckoutController(BookRepository bookRepository, UserRepository userRepository, RateLimitingService rateLimitingService) {
    this.bookRepository = bookRepository;
    this.userRepository = userRepository;
    this.rateLimitingService = rateLimitingService;
  }

  @PreAuthorize("hasRole('USER')")
  @PostMapping("/checkout")
  public String showCheckout(Model model,
                             Authentication authentication) {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Double totalPrice = user.getCart().entrySet().stream()
            .mapToDouble(entry -> {
              Book currentBook = bookRepository.findById(entry.getKey().getId()).orElse(null);
              if (currentBook == null) return 0;
              return currentBook.getPrice().doubleValue() * entry.getValue();
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
  @Transactional(isolation = Isolation.SERIALIZABLE)
  public String placeOrder(@RequestParam String cardNumber,
                           @RequestParam String cardOwner,
                           @RequestParam String expirationDate,
                           @RequestParam String cvv,
                           Authentication authentication,
                           RedirectAttributes redirectAttributes) throws BookNotFoundException {
    String clientIP = getClientIP();

    // Check rate limiting for order placement
    if (rateLimitingService.isBlocked(clientIP)) {
      logger.warn("Order attempts from Client IP {} were blocked. Too many order attempts.", clientIP);
      redirectAttributes.addFlashAttribute("error", "Too many order attempts. Please try again later.");
      return "redirect:/cart";
    }

    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Map<Book, Integer> booksInCart = user.getCart();

    // Validate cart is not empty
    if (booksInCart == null || booksInCart.isEmpty()) {
      redirectAttributes.addFlashAttribute("error", "Cannot checkout with empty cart");
      return "redirect:/cart";
    }

    // Validate payment fields
    try {
      validatePaymentFields(cardNumber, cardOwner, expirationDate, cvv);
    } catch (Exception e) {
      logger.warn("Payment validation failed for user {}: {}", Utilities.sanitizeLogInput(authentication.getName()), e.getMessage());
      redirectAttributes.addFlashAttribute("error", "Failed to validate payment information.");
      return "redirect:/cart";
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
      double itemTotal = book.getPrice().doubleValue() * quantity;
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
            orderId, Utilities.sanitizeLogInput(authentication.getName()), String.format("%.2f", totalPrice));

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

  private void validatePaymentFields(String cardNumber, String cardOwner, String expirationDate, String cvv) {
    if (cardNumber == null || cardNumber.trim().isEmpty()) {
      throw new IllegalArgumentException("Card number is required");
    }
    if (cardOwner == null || cardOwner.trim().isEmpty()) {
      throw new IllegalArgumentException("Card owner is required");
    }
    if (expirationDate == null || expirationDate.trim().isEmpty()) {
      throw new IllegalArgumentException("Expiration date is required");
    }
    if (cvv == null || cvv.trim().isEmpty()) {
      throw new IllegalArgumentException("CVV is required");
    }

    String cleanCardNumber = cardNumber.replaceAll("\\s+", "");
    if (!Pattern.matches("\\d{16,19}", cleanCardNumber) || !isValidCardNumber(cleanCardNumber)) {
      throw new IllegalArgumentException("Invalid card number format");
    }

    if (!Pattern.matches("[A-Za-z\\s]+", cardOwner.trim())) {
      throw new IllegalArgumentException("Invalid card owner name");
    }
    if (cardOwner.trim().length() > 50) {
      throw new IllegalArgumentException("Card owner name too long");
    }

    if (!Pattern.matches("(0[1-9]|1[0-2])/\\d{2}", expirationDate.trim())) {
      throw new IllegalArgumentException("Invalid expiration date format (MM/YY)");
    }

    if (!Pattern.matches("\\d{3,4}", cvv.trim())) {
      throw new IllegalArgumentException("Invalid CVV format");
    }
  }

  private String getClientIP() {
    try {
      ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
      if (attributes != null && attributes.getRequest() != null) {
        return attributes.getRequest().getRemoteAddr();
      }
    } catch (IllegalStateException e) {
      logger.debug("No request context available");
    }
    return "unknown";
  }

  private boolean isValidCardNumber(String cardNumber) {
    // Implement Luhn algorithm
    int sum = 0;
    boolean alternate = false;
    for (int i = cardNumber.length() - 1; i >= 0; i--) {
      int n = Integer.parseInt(cardNumber.substring(i, i + 1));
      if (alternate) {
        n *= 2;
        if (n > 9) n = (n % 10) + 1;
      }
      sum += n;
      alternate = !alternate;
    }
    return (sum % 10 == 0);
  }
}

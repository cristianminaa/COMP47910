package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.repository.BookRepository;
import com.cristianmina.comp47910.repository.UserRepository;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Positive;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
public class CartController {

  private static final Logger logger = LoggerFactory.getLogger(CartController.class);
  private final BookRepository bookRepository;
  private final UserRepository userRepository;

  public CartController(BookRepository bookRepository, UserRepository userRepository) {
    this.bookRepository = bookRepository;
    this.userRepository = userRepository;
  }


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
  @Transactional(isolation = Isolation.SERIALIZABLE)
  @PostMapping("/cart/{id}")
  public String addToCart(@PathVariable(value = "id") @Positive Long bookId,
                          @RequestParam(defaultValue = "1") @Min(1) @Max(99) int quantity,
                          Authentication authentication) throws BookNotFoundException {
    // Additional validation handled by @Positive annotation

    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));

    // Smart cart quantity adjustment
    int currentCartQuantity = user.getCart().getOrDefault(book, 0);
    int requestedTotal = currentCartQuantity + quantity;
    int availableStock = book.getNumberOfCopies();

    if (requestedTotal > availableStock) {
      // Adjust cart quantity to maximum available stock
      int adjustedQuantity = availableStock - currentCartQuantity;
      if (adjustedQuantity > 0) {
        user.addToCart(book, adjustedQuantity);
        logger.info("Cart quantity adjusted - Book ID: {}, Requested: {}, Current in cart: {}, Stock: {}, Added: {}, Final cart quantity: {}, User: {}",
                bookId, quantity, currentCartQuantity, availableStock, adjustedQuantity, availableStock, authentication.getName());
      } else {
        logger.info("No items added to cart - Book ID: {} already at maximum stock quantity {} in cart, User: {}",
                bookId, currentCartQuantity, authentication.getName());
      }
    } else {
      user.addToCart(book, quantity);
      logger.info("Adding to cart - Book ID: {}, Quantity: {}, User: {}", bookId, quantity, authentication.getName());
    }

    userRepository.save(user);
    return "redirect:/cart";
  }

  // Update Book Quantity in Cart
  @PreAuthorize("hasRole('USER')")
  @PutMapping("/cart/update/{id}")
  public String updateQuantityInCart(@PathVariable(value = "id") @Positive Long bookId,
                                     @RequestParam(defaultValue = "1") int quantity,
                                     Authentication authentication) throws BookNotFoundException {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
    user.setQuantityInCart(book, quantity);
    logger.info("Updating book quantity in cart - Book ID: {}, Quantity: {}, User: {}", bookId, quantity, authentication.getName());
    userRepository.save(user);
    return "redirect:/cart";
  }

  // Remove Book from Cart
  @PreAuthorize("hasRole('USER')")
  @DeleteMapping("/cart/delete/{id}")
  public String deleteFromCart(@PathVariable(value = "id") @Positive Long bookId,
                               Authentication authentication) throws BookNotFoundException {
    User user = userRepository.findByUsername(authentication.getName()).orElseThrow();
    Book book = bookRepository.findById(bookId).orElseThrow(() -> new BookNotFoundException(bookId));
    user.removeFromCart(book);
    logger.info("Removing book from cart - Book ID: {}, User: {}", bookId, authentication.getName());
    userRepository.save(user);
    return "redirect:/cart";
  }
}

package com.cristianmina.comp47910.security;

import com.cristianmina.comp47910.exceptions.BookNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@ControllerAdvice
public class GlobalExceptionHandler {
  private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

  @ExceptionHandler(BookNotFoundException.class)
  public String handleBookNotFound(BookNotFoundException ex, RedirectAttributes redirectAttributes) {
    logger.warn("Book not found: {}", ex.getMessage());
    redirectAttributes.addFlashAttribute("error", "The requested book was not found.");
    return "redirect:/books";
  }

  @ExceptionHandler(IllegalStateException.class)
  public String handleInsufficientStock(IllegalStateException ex, RedirectAttributes redirectAttributes) {
    logger.warn("Insufficient stock: {}", ex.getMessage());
    if (ex.getMessage().contains("Not enough copies")) {
      redirectAttributes.addFlashAttribute("error", "Unable to complete checkout. Please try again.");
      return "redirect:/cart";
    }
    redirectAttributes.addFlashAttribute("error", "Unable to complete your request. Please try again.");
    return "redirect:/books";
  }

  @ExceptionHandler(AccessDeniedException.class)
  public String handleAccessDenied(AccessDeniedException ex, RedirectAttributes redirectAttributes) {
    logger.warn("Access denied: {}", ex.getMessage());
    redirectAttributes.addFlashAttribute("error", "You don't have permission to access this resource.");
    return "redirect:/books";
  }

  @ExceptionHandler(ObjectOptimisticLockingFailureException.class)
  public String handleOptimisticLockingFailure(ObjectOptimisticLockingFailureException ex, RedirectAttributes redirectAttributes) {
    logger.warn("Optimistic locking failure: {}", ex.getMessage());
    redirectAttributes.addFlashAttribute("error", "Another user modified this item. Please try again.");
    return "redirect:/books";
  }

  @ExceptionHandler(IllegalArgumentException.class)
  public String handleIllegalArgument(IllegalArgumentException ex, RedirectAttributes redirectAttributes) {
    logger.warn("Invalid request: {}", ex.getMessage());
    redirectAttributes.addFlashAttribute("error", "Invalid request. Please check your input.");
    return "redirect:/books";
  }

  @ExceptionHandler(Exception.class)
  public String handleGenericException(Exception ex, RedirectAttributes redirectAttributes) {
    // Log full error internally for debugging
    logger.error("Unexpected application error", ex);

    // Show generic message to user for security
    redirectAttributes.addFlashAttribute("error", "An unexpected error occurred. Please try again later.");
    return "redirect:/books";
  }
}
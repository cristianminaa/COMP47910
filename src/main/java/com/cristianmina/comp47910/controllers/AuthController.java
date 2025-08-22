package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.model.UserRole;
import com.cristianmina.comp47910.repository.UserRepository;
import com.cristianmina.comp47910.security.PasswordValidator;
import com.cristianmina.comp47910.security.RateLimitingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDate;

@Controller
public class AuthController {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private BCryptPasswordEncoder passwordEncoder;

  @Autowired
  private PasswordValidator passwordValidator;

  @Autowired
  private RateLimitingService rateLimitingService;

  @GetMapping("/")
  public String showLoginForm() {
    return "index";
  }


  @GetMapping("/register")
  public String showRegisterForm(Model model) {
    model.addAttribute("user", new User());
    return "register";
  }

  @PostMapping("/register")
  public String processRegistration(@RequestParam String name,
                                    @RequestParam String surname,
                                    @RequestParam String dateOfBirth,
                                    @RequestParam String address,
                                    @RequestParam String phoneNumber,
                                    @RequestParam String emailAddress,
                                    @RequestParam String username,
                                    @RequestParam String password,
                                    RedirectAttributes redirectAttributes,
                                    HttpServletRequest request) {

    String clientIP = request.getRemoteAddr();

    if (rateLimitingService.isBlocked(clientIP)) {
      redirectAttributes.addFlashAttribute("error", "Too many registration attempts. Please try again later.");
      return "redirect:/register";
    }

    // Validate password first
    if (!passwordValidator.validate(password)) {
      redirectAttributes.addFlashAttribute("error", "Password must contain at least 8 characters, including uppercase, lowercase, number, and special character");
      return "redirect:/register";
    }

    // Check if username already exists
    if (userRepository.findByUsername(username).isPresent()) {
      redirectAttributes.addFlashAttribute("error", "Username already exists");
      return "redirect:/register";
    }

    try {
      User user = new User(
              name,
              surname,
              LocalDate.parse(dateOfBirth),
              address,
              phoneNumber,
              emailAddress,
              username,
              passwordEncoder.encode(password),
              UserRole.USER
      );
      userRepository.save(user);

      // Let Spring Security handle authentication instead of manual session
      redirectAttributes.addFlashAttribute("message", "Registration successful! Please log in.");
      return "redirect:/";
    } catch (Exception e) {
      redirectAttributes.addFlashAttribute("error", "Registration failed. Please try again.");
      return "redirect:/register";
    }
  }

  @GetMapping("/logout")
  public String showRegisterForm(HttpSession session) {
    session.removeAttribute("user");
    return "redirect:/";
  }
}
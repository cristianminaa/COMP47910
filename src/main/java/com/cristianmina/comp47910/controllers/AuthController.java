package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.model.UserRole;
import com.cristianmina.comp47910.repository.UserRepository;
import com.cristianmina.comp47910.security.PasswordValidator;
import com.cristianmina.comp47910.security.RateLimitingService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder passwordEncoder;
  private final PasswordValidator passwordValidator;
  private final RateLimitingService rateLimitingService;
  private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

  public AuthController(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder,
                        PasswordValidator passwordValidator, RateLimitingService rateLimitingService) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
    this.passwordValidator = passwordValidator;
    this.rateLimitingService = rateLimitingService;
  }

  @GetMapping("/")
  public String index(@RequestParam(value = "error", required = false) String error, Model model) {
    if (error != null) {
      model.addAttribute("error", "Invalid username or password.");
    }
    return "index";
  }


  @GetMapping("/register")
  public String showRegisterForm() {
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
    logger.info("Registration attempt from Client IP: {}", clientIP);

    // Rate limiting check
    if (rateLimitingService.isBlocked(clientIP)) {
      redirectAttributes.addFlashAttribute("error", "Too many registration attempts. Please try again later.");
      logger.warn("Registration attempts from Client IP {} were blocked. Too many registration attempts.", clientIP);
      return "redirect:/register";
    }

    // Validate password
    if (!passwordValidator.validate(password)) {
      redirectAttributes.addFlashAttribute("error", "Password must contain at least 8 characters, including uppercase, lowercase, number, and special character");
      logger.warn("Registration attempt from Client IP {} unsuccessful. Password does not meet complexity requirements.", clientIP);
      return "redirect:/register";
    }

    // Check username already exists
    if (userRepository.findByUsername(username).isPresent()) {
      redirectAttributes.addFlashAttribute("error", "Username already exists");
      logger.warn("Registration attempt from Client IP {} unsuccessful. Username already exists.", clientIP);
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

      redirectAttributes.addFlashAttribute("message", "Registration successful! Please log in.");
      logger.info("Registration attempt from Client IP {} successful.", clientIP);
      return "redirect:/";
    } catch (Exception e) {
      redirectAttributes.addFlashAttribute("error", "Registration failed. Please try again.");
      logger.warn("Registration attempt from Client IP {} failed.", clientIP);
      return "redirect:/register";
    }
  }

}
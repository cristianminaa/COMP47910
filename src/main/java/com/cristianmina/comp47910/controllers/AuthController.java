package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.dto.UserDto;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.repository.UserRepository;
import com.cristianmina.comp47910.security.PasswordValidator;
import com.cristianmina.comp47910.security.RateLimitingService;
import com.cristianmina.comp47910.service.DtoConversionService;
import com.cristianmina.comp47910.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.jboss.aerogear.security.otp.api.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AuthController {

  private final UserRepository userRepository;
  private final UserService userService;
  private final PasswordValidator passwordValidator;
  private final RateLimitingService rateLimitingService;
  private final DtoConversionService dtoConversionService;
  private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

  public AuthController(UserRepository userRepository, UserService userService,
                        PasswordValidator passwordValidator, RateLimitingService rateLimitingService,
                        DtoConversionService dtoConversionService) {
    this.userRepository = userRepository;
    this.userService = userService;
    this.passwordValidator = passwordValidator;
    this.rateLimitingService = rateLimitingService;
    this.dtoConversionService = dtoConversionService;
  }

  @GetMapping("/")
  public String index(@RequestParam(value = "error", required = false) String error, Model model) {
    if (error != null) {
      model.addAttribute("error", "Invalid credentials.");
    }
    return "index";
  }


  @GetMapping("/register")
  public String showRegisterForm(Model model) {
    model.addAttribute("userRegistration", new UserDto());
    return "register";
  }

  @PostMapping("/register")
  public String processRegistration(@Valid @ModelAttribute("userRegistration") UserDto registrationDto,
                                    BindingResult result,
                                    RedirectAttributes redirectAttributes,
                                    HttpServletRequest request,
                                    Model model) {

    String clientIP = request.getRemoteAddr();
    logger.info("Registration attempt from Client IP: {}", clientIP);

    // Rate limiting check
    if (rateLimitingService.isBlocked(clientIP)) {
      redirectAttributes.addFlashAttribute("error", "Too many registration attempts. Please try again later.");
      logger.warn("Registration attempts from Client IP {} were blocked. Too many registration attempts.", clientIP);
      return "redirect:/register";
    }

    // Check for validation errors
    if (result.hasErrors()) {
      logger.warn("Registration attempt from Client IP {} unsuccessful. Validation errors.", clientIP);
      return "register";
    }

    // Validate password
    if (!passwordValidator.validate(registrationDto.getPassword(), registrationDto.getUsername())) {
      result.rejectValue("password", "error.password",
              "Password must contain at least 12 characters, including uppercase, lowercase, number, and special character");
      logger.warn("Registration attempt from Client IP {} unsuccessful. Password does not meet complexity requirements.", clientIP);
      return "register";
    }

    // Check username already exists
    if (userRepository.findByUsername(registrationDto.getUsername()).isPresent()) {
      result.rejectValue("username", "error.username", "Username already exists");
      logger.warn("Registration attempt from Client IP {} unsuccessful. Username already exists.", clientIP);
      return "register";
    }

    // Check email already exists
    if (userRepository.findByEmailAddress(registrationDto.getEmailAddress()).isPresent()) {
      result.rejectValue("emailAddress", "error.email", "Email address already exists");
      logger.warn("Registration attempt from Client IP {} unsuccessful. Email already exists.", clientIP);
      return "register";
    }

    try {
      if (registrationDto.isUsing2FA()) {
        registrationDto.setSecret(Base32.random());
        model.addAttribute("qr", userService.generateQRUrl(registrationDto));
        User user = dtoConversionService.convertUserDtoToEntity(registrationDto);
        userRepository.save(user);
        return "qrcode";
      }
      User user = dtoConversionService.convertUserDtoToEntity(registrationDto);
      userRepository.save(user);

      redirectAttributes.addFlashAttribute("message", "Registration successful! Please log in.");
      logger.info("Registration attempt from Client IP {} successful.", clientIP);
      return "redirect:/";
    } catch (Exception e) {
      logger.error("Registration attempt from Client IP {} failed with exception: {}", clientIP, e.getMessage());
      result.reject("error.global", "Registration failed. Please try again.");
      return "register";
    }
  }

}
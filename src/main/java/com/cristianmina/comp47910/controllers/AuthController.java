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
import org.springframework.security.core.Authentication;
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
    if (passwordValidator.validate(registrationDto.getPassword(), registrationDto.getUsername())) {
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

  @GetMapping("/account")
  public String showAccountPage(Model model, Authentication authentication) {
    User currentUser = (User) authentication.getPrincipal();
    UserDto userDto = dtoConversionService.convertUserEntityToDto(currentUser);
    // Clear password for security - never send password to frontend
    userDto.setPassword("");
    model.addAttribute("user", userDto);
    return "account";
  }

  @PostMapping("/account")
  public String updateAccount(@ModelAttribute("user") UserDto userDto,
                              @RequestParam("currentPassword") String currentPassword,
                              @RequestParam(value = "newPassword", required = false) String newPassword,
                              BindingResult result,
                              Authentication authentication,
                              RedirectAttributes redirectAttributes,
                              HttpServletRequest request,
                              Model model) {

    String clientIP = request.getRemoteAddr();
    logger.info("Account update attempt from Client IP: {}", clientIP);

    User currentUser = (User) authentication.getPrincipal();

    // Verify current password first (required for all account changes)
    if (currentPassword == null || currentPassword.trim().isEmpty()) {
      result.reject("error.global", "Current password is required to make changes.");
      return "account";
    }

    if (!passwordValidator.verifyPassword(currentPassword, currentUser.getPassword())) {
      result.reject("error.global", "Current password is incorrect.");
      logger.warn("Account update attempt from Client IP {} unsuccessful. Incorrect current password.", clientIP);
      return "account";
    }

    // Only validate fields that are being updated (not empty/null)
    if (userDto.getName() != null && !userDto.getName().trim().isEmpty()) {
      if (userDto.getName().length() > 50 || !userDto.getName().matches("^[a-zA-Z\\s\\-.']+$")) {
        result.rejectValue("name", "error.name", "Invalid name format");
      }
    }

    if (userDto.getSurname() != null && !userDto.getSurname().trim().isEmpty()) {
      if (userDto.getSurname().length() > 50 || !userDto.getSurname().matches("^[a-zA-Z\\s\\-.']+$")) {
        result.rejectValue("surname", "error.surname", "Invalid surname format");
      }
    }

    if (userDto.getEmailAddress() != null && !userDto.getEmailAddress().trim().isEmpty()) {
      if (!userDto.getEmailAddress().matches("^[A-Za-z0-9+_.-]+@(.+)$") || userDto.getEmailAddress().length() > 100) {
        result.rejectValue("emailAddress", "error.email", "Invalid email format");
      }
    }

    if (userDto.getPhoneNumber() != null && !userDto.getPhoneNumber().trim().isEmpty()) {
      if (!userDto.getPhoneNumber().matches("^[+]?[(]?[0-9]{3}[)]?[-\\s.]?[0-9]{3}[-\\s.]?[0-9]{4,6}$")) {
        result.rejectValue("phoneNumber", "error.phone", "Invalid phone number format");
      }
    }

    if (userDto.getAddress() != null && !userDto.getAddress().trim().isEmpty()) {
      if (userDto.getAddress().length() > 200) {
        result.rejectValue("address", "error.address", "Address too long");
      }
    }

    // Validate new password only if provided
    if (newPassword != null && !newPassword.trim().isEmpty()) {
      if (passwordValidator.validate(newPassword, currentUser.getUsername())) {
        result.reject("error.global", "New password must contain at least 12 characters, including uppercase, lowercase, number, and special character");
        logger.warn("Account update attempt from Client IP {} unsuccessful. New password does not meet complexity requirements.", clientIP);
        return "account";
      }
    }

    if (result.hasErrors()) {
      logger.warn("Account update attempt from Client IP {} unsuccessful. Validation errors.", clientIP);
      return "account";
    }

    try {
      // Update only non-empty fields
      if (userDto.getName() != null && !userDto.getName().trim().isEmpty()) {
        currentUser.setName(userDto.getName().trim());
      }
      if (userDto.getSurname() != null && !userDto.getSurname().trim().isEmpty()) {
        currentUser.setSurname(userDto.getSurname().trim());
      }
      if (userDto.getEmailAddress() != null && !userDto.getEmailAddress().trim().isEmpty()) {
        currentUser.setEmailAddress(userDto.getEmailAddress().trim());
      }
      if (userDto.getAddress() != null && !userDto.getAddress().trim().isEmpty()) {
        currentUser.setAddress(userDto.getAddress().trim());
      }
      if (userDto.getDateOfBirth() != null) {
        currentUser.setDateOfBirth(userDto.getDateOfBirth());
      }
      if (userDto.getPhoneNumber() != null && !userDto.getPhoneNumber().trim().isEmpty()) {
        currentUser.setPhoneNumber(userDto.getPhoneNumber().trim());
      }

      // Update password only if new password provided
      if (newPassword != null && !newPassword.trim().isEmpty()) {
        currentUser.setPassword(newPassword);
      }

      // Handle 2FA toggle
      if (userDto.isUsing2FA() && !currentUser.isUsing2FA()) {
        // Enabling 2FA - generate new secret and show QR code
        userDto.setSecret(Base32.random());
        currentUser.setSecret(userDto.getSecret());
        currentUser.setUsing2FA(true);
        userRepository.save(currentUser);
        model.addAttribute("qr", userService.generateQRUrl(userDto));
        logger.info("Account update from Client IP {} - 2FA enabled.", clientIP);
        return "qrcode";
      } else if (!userDto.isUsing2FA() && currentUser.isUsing2FA()) {
        // Disabling 2FA
        currentUser.setUsing2FA(false);
        currentUser.setSecret(null);
        logger.info("Account update from Client IP {} - 2FA disabled.", clientIP);
      }

      userRepository.save(currentUser);
      redirectAttributes.addFlashAttribute("message", "Account updated successfully!");
      logger.info("Account update from Client IP {} successful.", clientIP);
      return "redirect:/account";

    } catch (Exception e) {
      logger.error("Account update from Client IP {} failed with exception: {}", clientIP, e.getMessage());
      result.reject("error.global", "Account update failed. Please try again.");
      return "account";
    }
  }

}
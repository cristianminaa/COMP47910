package com.cristianmina.comp47910.controllers;

import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.model.UserRole;
import com.cristianmina.comp47910.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.Objects;

@Controller
public class AuthController {

  @Autowired
  private UserRepository userRepository;

  @GetMapping("/")
  public String showLoginForm() {
    return "index";
  }

  @PostMapping("/")
  public String processLogin(@RequestParam String username,
                             @RequestParam String password,
                             Model model,
                             HttpSession session) {
    User user = userRepository.findByUsername(username).orElse(null);
    if (user != null && Objects.equals(user.getPassword(), password)) {
      session.setAttribute("user", user);
      return "redirect:/books";
    } else {
      model.addAttribute("error", "Invalid credentials");
      return "index";
    }
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
                                    Model model,
                                    HttpSession session) {
    User user = new User(
            name,
            surname,
            LocalDate.parse(dateOfBirth),
            address,
            phoneNumber,
            emailAddress,
            username,
            password,
            UserRole.USER
    );
    user = userRepository.save(user);
    session.setAttribute("user", user);
    return "redirect:/books";
  }

  @GetMapping("/logout")
  public String showRegisterForm(Model model,
                                 HttpSession session) {
    session.removeAttribute("user");
    return "redirect:/";
  }
}
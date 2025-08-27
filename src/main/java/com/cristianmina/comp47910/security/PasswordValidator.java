package com.cristianmina.comp47910.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class PasswordValidator {
  private static final int MIN_LENGTH = 12;
  private static final String PASSWORD_PATTERN = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?])(?=\\S+$).{12,}$";
  private final Pattern pattern = Pattern.compile(PASSWORD_PATTERN);

  @Autowired
  private BCryptPasswordEncoder passwordEncoder;

  public boolean validate(String password, String username) {
    if (password.length() < MIN_LENGTH) return true;
    if (!pattern.matcher(password).matches()) return true;
    if (password.toLowerCase().contains(username.toLowerCase())) return true;
    if (isCommonPassword(password)) return true; // Check against list
    if (hasRepetitivePatterns(password)) return true;
    return false;
  }

  public boolean verifyPassword(String rawPassword, String encodedPassword) {
    return passwordEncoder.matches(rawPassword, encodedPassword);
  }


  private boolean isCommonPassword(String password) {
    // Usually retrieved from a database or file
    String[] commonPasswords = {"password", "123456", "123456789", "qwerty", "abc123", "letmein", "monkey", "football"};
    for (String common : commonPasswords) {
      if (password.equalsIgnoreCase(common)) {
        return true;
      }
    }
    return false;
  }

  private boolean hasRepetitivePatterns(String password) {
    // Checks for 3 or more repeated characters or sequences
    return Pattern.compile("(.)\\1{2,}").matcher(password).find();
  }
}
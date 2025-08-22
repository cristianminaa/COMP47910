package com.cristianmina.comp47910.security;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class PasswordValidator {
  private static final String PASSWORD_PATTERN =
          "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$";

  private final Pattern pattern = Pattern.compile(PASSWORD_PATTERN);

  public boolean validate(String password) {
    return pattern.matcher(password).matches();
  }
}
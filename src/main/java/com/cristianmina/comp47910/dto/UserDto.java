package com.cristianmina.comp47910.dto;

import com.cristianmina.comp47910.model.User;
import jakarta.validation.constraints.*;

import java.time.LocalDate;

public class UserDto {

  @NotBlank(message = "Name is required")
  @Size(max = 50, message = "Name cannot exceed 50 characters")
  @Pattern(regexp = "^[a-zA-Z\\s\\-.']+$", message = "Name contains invalid characters")
  private String name;

  @NotBlank(message = "Surname is required")
  @Size(max = 50, message = "Surname cannot exceed 50 characters")
  @Pattern(regexp = "^[a-zA-Z\\s\\-.']+$", message = "Surname contains invalid characters")
  private String surname;

  @NotNull(message = "Date of birth is required")
  @Past(message = "Date of birth must be in the past")
  private LocalDate dateOfBirth;

  @NotBlank(message = "Address is required")
  @Size(max = 200, message = "Address cannot exceed 200 characters")
  private String address;

  @NotBlank(message = "Phone number is required")
  @Pattern(regexp = "^[+]?[(]?[0-9]{3}[)]?[-\\s.]?[0-9]{3}[-\\s.]?[0-9]{4,6}$",
          message = "Invalid phone number format")
  private String phoneNumber;

  @NotBlank(message = "Email address is required")
  @Email(message = "Invalid email format")
  @Size(max = 100, message = "Email cannot exceed 100 characters")
  private String emailAddress;

  @NotBlank(message = "Username is required")
  @Size(min = 3, max = 30, message = "Username must be between 3 and 30 characters")
  @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, and underscores")
  private String username;

  @NotBlank(message = "Password is required")
  @Size(min = 12, message = "Password must be at least 12 characters")
  private String password;

  private boolean isUsing2FA;
  private String secret;

  public UserDto() {
  }

  public UserDto(String name, String surname, LocalDate dateOfBirth, String address,
                 String phoneNumber, String emailAddress, String username, String password) {
    this.name = name;
    this.surname = surname;
    this.dateOfBirth = dateOfBirth;
    this.address = address;
    this.phoneNumber = phoneNumber;
    this.emailAddress = emailAddress;
    this.username = username;
    this.password = password;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getSurname() {
    return surname;
  }

  public void setSurname(String surname) {
    this.surname = surname;
  }

  public LocalDate getDateOfBirth() {
    return dateOfBirth;
  }

  public void setDateOfBirth(LocalDate dateOfBirth) {
    this.dateOfBirth = dateOfBirth;
  }

  public String getAddress() {
    return address;
  }

  public void setAddress(String address) {
    this.address = address;
  }

  public String getPhoneNumber() {
    return phoneNumber;
  }

  public void setPhoneNumber(String phoneNumber) {
    this.phoneNumber = phoneNumber;
  }

  public String getEmailAddress() {
    return emailAddress;
  }

  public void setEmailAddress(String emailAddress) {
    this.emailAddress = emailAddress;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public boolean isUsing2FA() {
    return isUsing2FA;
  }

  public void setUsing2FA(boolean using2FA) {
    isUsing2FA = using2FA;
  }

  public String getSecret() {
    return secret;
  }

  public void setSecret(String secret) {
    this.secret = secret;
  }

  // Security: Method to safely check if secret exists without exposing it
  public boolean hasSecret() {
    return secret != null && !secret.trim().isEmpty();
  }

  // Conversion methods
  public static UserDto fromEntity(User user) {
    UserDto dto = new UserDto();
    dto.setName(user.getName());
    dto.setSurname(user.getSurname());
    dto.setDateOfBirth(user.getDateOfBirth());
    dto.setAddress(user.getAddress());
    dto.setPhoneNumber(user.getPhoneNumber());
    dto.setEmailAddress(user.getEmailAddress());
    dto.setUsername(user.getUsername());
    dto.setUsing2FA(user.isUsing2FA());
    // Security: Never expose the secret in DTOs used for display
    // Note: Password is not included for security reasons
    return dto;
  }

  public User toEntity() {
    User user = new User();
    user.setName(this.name);
    user.setSurname(this.surname);
    user.setDateOfBirth(this.dateOfBirth);
    user.setAddress(this.address);
    user.setPhoneNumber(this.phoneNumber);
    user.setEmailAddress(this.emailAddress);
    user.setUsername(this.username);
    user.setUsing2FA(this.isUsing2FA);
    if (this.hasSecret()) {
      user.setSecret(this.secret);
    }
    // Note: Password encoding should be handled by the service layer
    return user;
  }
}
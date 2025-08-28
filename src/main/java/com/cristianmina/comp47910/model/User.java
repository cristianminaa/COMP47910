package com.cristianmina.comp47910.model;

import com.cristianmina.comp47910.security.CryptoConverter;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Entity
@Table(
        name = "user",
        indexes = {
                @Index(columnList = "username"),
                @Index(columnList = "emailAddress")
        }
)
@Inheritance(strategy = InheritanceType.JOINED)
public class User implements UserDetails {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @NotBlank
  private String name;
  @NotBlank
  private String surname;
  @NotNull
  private LocalDate dateOfBirth;
  @NotBlank
  private String address;
  @NotBlank
  @Pattern(regexp = "^[+]?[(]?[0-9]{3}[)]?[-\\s.]?[0-9]{3}[-\\s.]?[0-9]{4,6}$",
          message = "Invalid phone number format")
  private String phoneNumber;
  @NotBlank
  @Column(unique = true)
  private String emailAddress;

  @NotBlank
  @Column(unique = true)
  private String username;
  @NotBlank
  private String password;
  private boolean isUsing2FA;
  
  @Convert(converter = CryptoConverter.class)
  private String secret;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "user_cart", joinColumns = @JoinColumn(name = "user_id"))
  @MapKeyJoinColumn(name = "book_id")
  @Column(name = "quantity")
  private Map<Book, Integer> cart = new HashMap<>();

  @Enumerated(EnumType.STRING)
  private UserRole role;

  public User() {
  }

  public User(String name, String surname, LocalDate dateOfBirth, String address, String phoneNumber, String emailAddress, String username, String password, UserRole role) {
    this.name = name;
    this.surname = surname;
    this.dateOfBirth = dateOfBirth;
    this.address = address;
    this.phoneNumber = phoneNumber;
    this.emailAddress = emailAddress;
    this.username = username;
    this.password = password;
    this.cart = new HashMap<>();
    this.role = role;
  }

  public Long getId() {
    return id;
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

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of(() -> "ROLE_" + role.name());
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public UserRole getRole() {
    return role;
  }

  public void setRole(UserRole role) {
    this.role = role;
  }

  public Map<Book, Integer> getCart() {
    if (cart == null) {
      cart = new HashMap<>();
    }
    return cart;
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

  public void setCart(Map<Book, Integer> cart) {
    this.cart = cart;
  }

  public void addToCart(Book book, int quantity) {
    cart.merge(book, quantity, Integer::sum);
  }

  public void setQuantityInCart(Book book, int quantity) {
    // Validate inputs
    if (quantity < 0) {
      throw new IllegalArgumentException("Quantity cannot be negative");
    }

    if (quantity > 99) {
      throw new IllegalArgumentException("Cannot add more than 99 items");
    }

    if (quantity > book.getNumberOfCopies()) {
      throw new IllegalArgumentException("Not enough stock");
    }

    if (quantity < 1) {
      cart.remove(book);
    } else {
      cart.put(book, quantity);
    }
  }

  public void removeFromCart(Book book) {
    cart.remove(book);
  }

  public void clearCart() {
    cart.clear();
  }
}
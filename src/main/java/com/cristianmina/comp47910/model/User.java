package com.cristianmina.comp47910.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;

import java.time.LocalDate;
import java.util.HashMap;
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
public class User {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @NotBlank
  private String name;
  @NotBlank
  private String surname;
  @NotBlank
  private LocalDate dateOfBirth;
  @NotBlank
  private String address;
  @NotBlank
  private String phoneNumber;
  @NotBlank
  @Column(unique = true)
  private String emailAddress;

  @NotBlank
  @Column(unique = true)
  private String username;
  @NotBlank
  private String password;

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

  public void setCart(Map<Book, Integer> cart) {
    this.cart = cart;
  }

  public void addToCart(Book book, int quantity) {
    cart.merge(book, quantity, Integer::sum);
  }

  public void setQuantityInCart(Book book, int quantity) {
    if (cart.containsKey(book)) {
      if (quantity > 0) {
        cart.put(book, quantity);
      } else {
        cart.remove(book);
      }
    }
  }

  public void removeFromCart(Book book) {
    cart.remove(book);
  }

  public void clearCart() {
    cart.clear();
  }
}
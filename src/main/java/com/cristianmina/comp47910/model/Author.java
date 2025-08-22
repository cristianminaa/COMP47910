package com.cristianmina.comp47910.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

@Entity
@Table(name = "authors")
public class Author {

  @Id
  @GeneratedValue
  private Long id;

  @NotBlank
  @Size(max = 50)
  @Pattern(regexp = "^[a-zA-Z\\s\\-.']+$", message = "Invalid characters in name")
  private String firstName;

  @NotBlank
  @Size(max = 50)
  @Pattern(regexp = "^[a-zA-Z\\s\\-.']+$", message = "Invalid characters in name")
  private String lastName;

  @ManyToMany
  private List<Book> books;

  public Author() {
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getFirstName() {
    return firstName;
  }

  public void setFirstName(String authorFirstName) {
    this.firstName = authorFirstName;
  }

  public String getLastName() {
    return lastName;
  }

  public void setLastName(String authorLastName) {
    this.lastName = authorLastName;
  }

  public String getFullName() {
    return firstName + " " + lastName;
  }

  public List<Book> getBooks() {
    return books;
  }

  public void setBooks(List<Book> books) {
    this.books = books;
  }


}

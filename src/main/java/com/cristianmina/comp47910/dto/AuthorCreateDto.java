package com.cristianmina.comp47910.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

public class AuthorCreateDto {

  @NotBlank(message = "First name is required")
  @Size(max = 50, message = "First name cannot exceed 50 characters")
  @Pattern(regexp = "^[a-zA-Z\\s\\-.']+$", message = "First name contains invalid characters")
  private String firstName;

  @NotBlank(message = "Last name is required")
  @Size(max = 50, message = "Last name cannot exceed 50 characters")
  @Pattern(regexp = "^[a-zA-Z\\s\\-.']+$", message = "Last name contains invalid characters")
  private String lastName;

  @Size(max = 50, message = "Cannot select more than 50 books")
  private List<Long> bookIds;

  public AuthorCreateDto() {
  }

  public AuthorCreateDto(String firstName, String lastName, List<Long> bookIds) {
    this.firstName = firstName;
    this.lastName = lastName;
    this.bookIds = bookIds;
  }

  public String getFirstName() {
    return firstName;
  }

  public void setFirstName(String firstName) {
    this.firstName = firstName;
  }

  public String getLastName() {
    return lastName;
  }

  public void setLastName(String lastName) {
    this.lastName = lastName;
  }

  public List<Long> getBookIds() {
    return bookIds;
  }

  public void setBookIds(List<Long> bookIds) {
    this.bookIds = bookIds;
  }

  // Conversion methods
  public static AuthorCreateDto fromEntity(com.cristianmina.comp47910.model.Author author) {
    AuthorCreateDto dto = new AuthorCreateDto();
    dto.setFirstName(author.getFirstName());
    dto.setLastName(author.getLastName());
    if (author.getBooks() != null) {
      dto.setBookIds(author.getBooks().stream()
        .map(com.cristianmina.comp47910.model.Book::getId)
        .toList());
    }
    return dto;
  }

  public com.cristianmina.comp47910.model.Author toEntity() {
    com.cristianmina.comp47910.model.Author author = new com.cristianmina.comp47910.model.Author();
    author.setFirstName(this.firstName);
    author.setLastName(this.lastName);
    return author;
  }
}
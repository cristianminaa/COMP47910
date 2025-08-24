package com.cristianmina.comp47910.dto;

import jakarta.validation.constraints.*;

import java.util.List;

public class AuthorUpdateDto {

  @NotNull(message = "Author ID is required")
  @Positive(message = "Author ID must be positive")
  private Long id;

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

  public AuthorUpdateDto() {
  }

  public AuthorUpdateDto(Long id, String firstName, String lastName, List<Long> bookIds) {
    this.id = id;
    this.firstName = firstName;
    this.lastName = lastName;
    this.bookIds = bookIds;
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
  public static AuthorUpdateDto fromEntity(com.cristianmina.comp47910.model.Author author) {
    AuthorUpdateDto dto = new AuthorUpdateDto();
    dto.setId(author.getId());
    dto.setFirstName(author.getFirstName());
    dto.setLastName(author.getLastName());
    if (author.getBooks() != null) {
      dto.setBookIds(author.getBooks().stream()
        .map(com.cristianmina.comp47910.model.Book::getId)
        .toList());
    }
    return dto;
  }

  public void updateEntity(com.cristianmina.comp47910.model.Author author) {
    author.setFirstName(this.firstName);
    author.setLastName(this.lastName);
  }
}
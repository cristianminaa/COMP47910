package com.cristianmina.comp47910.dto;

import com.cristianmina.comp47910.model.Author;
import com.cristianmina.comp47910.model.Book;
import jakarta.validation.constraints.*;

import java.math.BigDecimal;
import java.util.List;

public class BookUpdateDto {

  @NotNull(message = "Book ID is required")
  @Positive(message = "Book ID must be positive")
  private Long id;

  @NotBlank(message = "Book title is required")
  @Size(max = 100, message = "Book title cannot exceed 100 characters")
  @Pattern(regexp = "^[a-zA-Z0-9\\s\\-.,!?'\"]+$", message = "Book title contains invalid characters")
  private String title;

  @NotNull(message = "Price is required")
  @DecimalMin(value = "0.0", inclusive = false, message = "Price must be greater than 0")
  @DecimalMax(value = "9999.99", message = "Price cannot exceed 9999.99")
  private BigDecimal price;

  @Min(value = 1000, message = "Year must be at least 1000")
  @Max(value = 2030, message = "Year cannot be in the future")
  private Integer year;

  @Min(value = 0, message = "Number of copies cannot be negative")
  @Max(value = 10000, message = "Number of copies cannot exceed 10000")
  private Integer numberOfCopies;

  @Size(max = 50, message = "Cannot select more than 50 authors")
  private List<Long> authorIds;

  public BookUpdateDto() {
  }

  public BookUpdateDto(Long id, String title, BigDecimal price, Integer year, Integer numberOfCopies, List<Long> authorIds) {
    this.id = id;
    this.title = title;
    this.price = price;
    this.year = year;
    this.numberOfCopies = numberOfCopies;
    this.authorIds = authorIds;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getTitle() {
    return title;
  }

  public void setTitle(String title) {
    this.title = title;
  }

  public BigDecimal getPrice() {
    return price;
  }

  public void setPrice(BigDecimal price) {
    this.price = price;
  }

  public Integer getYear() {
    return year;
  }

  public void setYear(Integer year) {
    this.year = year;
  }

  public Integer getNumberOfCopies() {
    return numberOfCopies;
  }

  public void setNumberOfCopies(Integer numberOfCopies) {
    this.numberOfCopies = numberOfCopies;
  }

  public List<Long> getAuthorIds() {
    return authorIds;
  }

  public void setAuthorIds(List<Long> authorIds) {
    this.authorIds = authorIds;
  }

  // Conversion methods
  public static BookUpdateDto fromEntity(Book book) {
    BookUpdateDto dto = new BookUpdateDto();
    dto.setId(book.getId());
    dto.setTitle(book.getTitle());
    dto.setPrice(book.getPrice());
    dto.setYear(book.getYear());
    dto.setNumberOfCopies(book.getNumberOfCopies());
    if (book.getAuthors() != null) {
      dto.setAuthorIds(book.getAuthors().stream()
              .map(Author::getId)
              .toList());
    }
    return dto;
  }

  public void updateEntity(Book book) {
    book.setTitle(this.title);
    book.setPrice(this.price);
    book.setYear(this.year);
    book.setNumberOfCopies(this.numberOfCopies);
  }
}
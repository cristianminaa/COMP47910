package com.cristianmina.comp47910.service;

import com.cristianmina.comp47910.dto.*;
import com.cristianmina.comp47910.model.Author;
import com.cristianmina.comp47910.model.Book;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.model.UserRole;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class DtoConversionService {

  private final BCryptPasswordEncoder passwordEncoder;

  public DtoConversionService(BCryptPasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  // User conversions
  public User convertUserDtoToEntity(UserDto userDto) {
    User user = new User();
    user.setName(userDto.getName());
    user.setSurname(userDto.getSurname());
    user.setDateOfBirth(userDto.getDateOfBirth());
    user.setAddress(userDto.getAddress());
    user.setPhoneNumber(userDto.getPhoneNumber());
    user.setEmailAddress(userDto.getEmailAddress());
    user.setUsername(userDto.getUsername());
    user.setPassword(passwordEncoder.encode(userDto.getPassword()));
    user.setRole(UserRole.USER);
    user.setUsing2FA(userDto.isUsing2FA());
    user.setSecret(userDto.getSecret());
    return user;
  }

  public UserDto convertUserEntityToDto(User user) {
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
    // Secret should only be available during registration process
    return dto;
  }

  // Author conversions
  public Author convertAuthorCreateDtoToEntity(AuthorCreateDto dto) {
    Author author = new Author();
    author.setFirstName(dto.getFirstName());
    author.setLastName(dto.getLastName());
    return author;
  }

  public AuthorCreateDto convertAuthorEntityToCreateDto(Author author) {
    AuthorCreateDto dto = new AuthorCreateDto();
    dto.setFirstName(author.getFirstName());
    dto.setLastName(author.getLastName());
    if (author.getBooks() != null) {
      dto.setBookIds(author.getBooks().stream()
              .map(Book::getId)
              .collect(Collectors.toList()));
    }
    return dto;
  }

  public AuthorUpdateDto convertAuthorEntityToUpdateDto(Author author) {
    AuthorUpdateDto dto = new AuthorUpdateDto();
    dto.setId(author.getId());
    dto.setFirstName(author.getFirstName());
    dto.setLastName(author.getLastName());
    if (author.getBooks() != null) {
      dto.setBookIds(author.getBooks().stream()
              .map(Book::getId)
              .collect(Collectors.toList()));
    }
    return dto;
  }

  public void updateAuthorEntityFromDto(Author author, AuthorUpdateDto dto) {
    author.setFirstName(dto.getFirstName());
    author.setLastName(dto.getLastName());
  }

  // Book conversions
  public Book convertBookCreateDtoToEntity(BookCreateDto dto) {
    Book book = new Book();
    book.setTitle(dto.getTitle());
    book.setPrice(dto.getPrice());
    book.setYear(dto.getYear());
    book.setNumberOfCopies(dto.getNumberOfCopies());
    return book;
  }

  public BookCreateDto convertBookEntityToCreateDto(Book book) {
    BookCreateDto dto = new BookCreateDto();
    dto.setTitle(book.getTitle());
    dto.setPrice(book.getPrice());
    dto.setYear(book.getYear());
    dto.setNumberOfCopies(book.getNumberOfCopies());
    if (book.getAuthors() != null) {
      dto.setAuthorIds(book.getAuthors().stream()
              .map(Author::getId)
              .collect(Collectors.toList()));
    }
    return dto;
  }

  public BookUpdateDto convertBookEntityToUpdateDto(Book book) {
    BookUpdateDto dto = new BookUpdateDto();
    dto.setId(book.getId());
    dto.setTitle(book.getTitle());
    dto.setPrice(book.getPrice());
    dto.setYear(book.getYear());
    dto.setNumberOfCopies(book.getNumberOfCopies());
    if (book.getAuthors() != null) {
      dto.setAuthorIds(book.getAuthors().stream()
              .map(Author::getId)
              .collect(Collectors.toList()));
    }
    return dto;
  }

  public void updateBookEntityFromDto(Book book, BookUpdateDto dto) {
    book.setTitle(dto.getTitle());
    book.setPrice(dto.getPrice());
    book.setYear(dto.getYear());
    book.setNumberOfCopies(dto.getNumberOfCopies());
  }

  // Bulk conversion methods
  public List<AuthorCreateDto> convertAuthorEntitiesToCreateDtos(List<Author> authors) {
    return authors.stream()
            .map(this::convertAuthorEntityToCreateDto)
            .collect(Collectors.toList());
  }

  public List<BookCreateDto> convertBookEntitiesToCreateDtos(List<Book> books) {
    return books.stream()
            .map(this::convertBookEntityToCreateDto)
            .collect(Collectors.toList());
  }
}
package com.cristianmina.comp47910.exceptions;

public class BookNotFoundException extends Exception {
  private long bookId;
  public BookNotFoundException(long bookId) {
    super(String.format("Book with ID %d not found", bookId));
  }
}

package com.cristianmina.comp47910.exceptions;

public class AuthorNotFoundException extends Exception{
    private long author_id;
    public AuthorNotFoundException(long author_id) {
        super(String.format("Author with ID '%s' not found.", author_id));
    }

}

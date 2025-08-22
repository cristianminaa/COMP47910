package com.cristianmina.comp47910.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name="books")
public class Book {

    @Id
    @GeneratedValue
    private Long id;

    @NotBlank
    private String name;

    @ManyToMany
    @JoinTable(
            name = "authorship",
            joinColumns = @JoinColumn(name = "id"),
            inverseJoinColumns = @JoinColumn(name = "author_id"))
    private List<Author> authors;

    @NotNull
    private Double price;

    private int year;
    private int numberOfCopies;

    public Book() {
        super();
    }

    public Book(Long id, String name, List<Author> authors, Double price, int year, int numberOfCopies) {
        this.id = id;
        this.name = name;
        this.authors = authors;
        this.price = price;
        this.year = year;
        this.numberOfCopies = numberOfCopies;
    }

    public String getTitle() {
        return name;
    }
    public void setTitle(String name) {
        this.name = name;
    }

    public void addAuthor(Author author) {
        this.authors.add(author);
    }
    public void removeAuthor(Author author) {
        this.authors.remove(author);
    }
    public List<Author> getAuthors() {
        return authors;
    }
    public String getAuthorNames() {
        return authors.stream().map(Author::getFullName).collect(Collectors.joining(", "));
    }
    public void setAuthors(List<Author> authors) {
        this.authors = authors;
    }

    public Long getId(){
        return id;
    }
    public void setId(Long id){
        this.id = id;
    }

    public Double getPrice(){
        return price;
    }
    public void setPrice(Double price){
        this.price = price;
    }

    public int getYear() {
        return year;
    }
    public void setYear(int year) {
        this.year = year;
    }

    public int getNumberOfCopies() {
        return numberOfCopies;
    }
    public void setNumberOfCopies(int numberOfCopies) {
        this.numberOfCopies = numberOfCopies;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Book book = (Book) o;
        return id != null && id.equals(book.id);
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }
}
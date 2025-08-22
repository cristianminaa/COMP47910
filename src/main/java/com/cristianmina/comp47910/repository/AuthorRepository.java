package com.cristianmina.comp47910.repository;

import com.cristianmina.comp47910.model.Author;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorRepository extends JpaRepository<Author, Long> { }
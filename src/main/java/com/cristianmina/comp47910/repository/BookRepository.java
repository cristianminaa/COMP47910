package com.cristianmina.comp47910.repository;

import com.cristianmina.comp47910.model.Book;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BookRepository extends JpaRepository<Book, Long> {
  @Query("SELECT b FROM Book b WHERE b.id = :id")
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  Optional<Book> findByIdForUpdate(@Param("id") Long id);
}
package com.cristianmina.comp47910.model;

import jakarta.persistence.Entity;

import java.time.LocalDate;

@Entity
public class Admin extends User {
    public Admin() {
        super();
    }

    public Admin(String name, String surname, LocalDate dateOfBirth, String address, String phoneNumber, String emailAddress, String username, String password) {
        super(name, surname, dateOfBirth, address, phoneNumber, emailAddress, username, password, UserRole.ADMIN);
    }
}
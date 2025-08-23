package com.cristianmina.comp47910;

import com.cristianmina.comp47910.model.Admin;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.model.UserRole;
import com.cristianmina.comp47910.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.HiddenHttpMethodFilter;

import java.time.LocalDate;

@SpringBootApplication
@EnableScheduling
public class Comp47910Application {

  public static void main(String[] args) {
    SpringApplication.run(Comp47910Application.class, args);
  }

  @Bean
  public HiddenHttpMethodFilter hiddenHttpMethodFilter() {
    return new HiddenHttpMethodFilter();
  }

  @Autowired
  private BCryptPasswordEncoder passwordEncoder;

  @Bean
  public CommandLineRunner createBaseUsers(UserRepository userRepository) {
    return args -> {
      String adminUsername = "admin";
      if (userRepository.findByUsername(adminUsername).isEmpty()) {
        Admin admin = new Admin(
                "AdminName",
                "AdminSurname",
                LocalDate.of(1998, 2, 4),
                "Admin Address",
                "123-456-7890",
                "cristian-daniel.mina@ucdconnect.ie",
                adminUsername,
                passwordEncoder.encode(adminUsername)
        );
        userRepository.save(admin);
        System.out.println("Admin user created: " + adminUsername);
      }
      String userUsername = "user";
      if (userRepository.findByUsername(userUsername).isEmpty()) {
        User user = new User(
                "UserName",
                "UserSurname",
                LocalDate.of(1990, 1, 1),
                "User Address",
                "111-111-1111",
                "user@bookshop.com",
                userUsername,
                passwordEncoder.encode(userUsername),
                UserRole.USER
        );
        userRepository.save(user);
        System.out.println("User created: " + userUsername);
      }
    };
  }

}

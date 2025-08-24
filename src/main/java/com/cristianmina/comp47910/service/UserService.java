package com.cristianmina.comp47910.service;

import com.cristianmina.comp47910.dto.UserDto;
import com.cristianmina.comp47910.model.User;

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Optional;

public interface UserService {
  void saveUser(UserDto userDto);

  Optional<User> findByEmail(String email);

  List<UserDto> findAllUsers();

  String generateQRUrl(UserDto user) throws UnsupportedEncodingException;

  public UserDto updateUser2FA(boolean use2FA);

}

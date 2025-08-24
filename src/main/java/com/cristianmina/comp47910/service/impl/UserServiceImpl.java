package com.cristianmina.comp47910.service.impl;

import com.cristianmina.comp47910.dto.UserDto;
import com.cristianmina.comp47910.model.User;
import com.cristianmina.comp47910.repository.UserRepository;
import com.cristianmina.comp47910.service.DtoConversionService;
import com.cristianmina.comp47910.service.UserService;
import org.jboss.aerogear.security.otp.api.Base32;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {
  public static String QR_PREFIX =
          "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=";


  private final UserRepository userRepository;
  private final DtoConversionService dtoConversionService;

  public UserServiceImpl(UserRepository userRepository,
                         DtoConversionService dtoConversionService) {
    this.userRepository = userRepository;
    this.dtoConversionService = dtoConversionService;
  }

  @Override
  public String generateQRUrl(UserDto user) throws UnsupportedEncodingException {
    String issuer = "BookShop"; // Shown in Authenticator
    String label = user.getEmailAddress();
    // Construct otpauth URI
    String otpauth = "otpauth://totp/"
            + URLEncoder.encode(issuer + ":" + label, StandardCharsets.UTF_8)
            + "?secret=" + URLEncoder.encode(user.getSecret(), StandardCharsets.UTF_8)
            + "&issuer=" + URLEncoder.encode(issuer, StandardCharsets.UTF_8);

    // Use QuickChart instead of deprecated Google Charts
    String qrUrl = "https://quickchart.io/qr?size=200&text=" +
            URLEncoder.encode(otpauth, StandardCharsets.UTF_8);

    return qrUrl;
  }


  @Override
  public void saveUser(UserDto userDto) {
    User user = dtoConversionService.convertUserDtoToEntity(userDto);
    userRepository.save(user);
  }

  @Override
  public UserDto updateUser2FA(boolean use2FA) {
    Authentication curAuth = SecurityContextHolder.getContext().getAuthentication();

    User currentUser = (User) curAuth.getPrincipal();

    currentUser.setUsing2FA(use2FA);
    currentUser.setSecret(Base32.random());

    currentUser = userRepository.save(currentUser);
    return dtoConversionService.convertUserEntityToDto(currentUser);
  }


  @Override
  public Optional<User> findByEmail(String email) {
    return userRepository.findByEmailAddress(email);
  }

  @Override
  public List<UserDto> findAllUsers() {
    List<User> users = userRepository.findAll();
    return users.stream()
            .map(dtoConversionService::convertUserEntityToDto)
            .collect(Collectors.toList());
  }

}

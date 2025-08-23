package com.cristianmina.comp47910.security;

public class Utilities {
  public static String sanitizeLogInput(String input) {
    if (input == null) return "null";
    return input.replaceAll("[\r\n]", "_")
            .replaceAll("\\p{Cntrl}", "");
  }
}

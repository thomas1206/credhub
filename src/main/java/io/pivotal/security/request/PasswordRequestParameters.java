package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect
public class PasswordRequestParameters {

  private int length;

  private boolean excludeLower;

  private boolean excludeNumber;

  private boolean excludeUpper;

  private boolean includeSpecial;

  private boolean onlyHex;

  public int getLength() {
    return length;
  }

  public void setLength(int length) {
    this.length = length;
  }

  public boolean isExcludeLower() {
    return excludeLower;
  }

  public void setExcludeLower(boolean excludeLower) {
    this.excludeLower = excludeLower;
  }

  public boolean isExcludeNumber() {
    return excludeNumber;
  }

  public void setExcludeNumber(boolean excludeNumber) {
    this.excludeNumber = excludeNumber;
  }

  public boolean isExcludeUpper() {
    return excludeUpper;
  }

  public void setExcludeUpper(boolean excludeUpper) {
    this.excludeUpper = excludeUpper;
  }

  public boolean isIncludeSpecial() {
    return includeSpecial;
  }

  public void setIncludeSpecial(boolean includeSpecial) {
    this.includeSpecial = includeSpecial;
  }

  public boolean isOnlyHex() {
    return onlyHex;
  }

  public void setOnlyHex(boolean onlyHex) {
    this.onlyHex = onlyHex;
  }

  public Boolean isValid() {
    return !(excludeSpecialChars()
      && exludeAlphaNumeric()
      && excludeHexChars());
  }

  private boolean excludeHexChars() {
    return !onlyHex;
  }

  private boolean excludeSpecialChars() {
    return !includeSpecial;
  }

  private boolean exludeAlphaNumeric() {
    return excludeNumber
      && excludeUpper
      && excludeLower;
  }
}

package io.pivotal.security.credential;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonValue;
import io.pivotal.security.request.StringGenerationParameters;

public class StringCredential implements CredentialValue {

  private final String string;
  private StringGenerationParameters generationParameters;

  public StringCredential(String password) {
    this.string = password;
  }

  @JsonValue
  public String getStringCredential() {
    return string;
  }

  @JsonIgnore
  public StringGenerationParameters getGenerationParameters() {
    return generationParameters;
  }

  public void setGenerationParameters(StringGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }
}

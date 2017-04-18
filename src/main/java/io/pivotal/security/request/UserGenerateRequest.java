package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.secret.User;
import io.pivotal.security.service.GeneratorService;

public class UserGenerateRequest extends BaseSecretGenerateRequest {

  @JsonProperty("parameters")
  private String generationParameters;

  @Override
  public void validate() {
    super.validate();
  }

  public BaseSecretSetRequest generateSetRequest(GeneratorService generatorService) {
    UserSetRequest userSetRequest = new UserSetRequest();
    userSetRequest.setType(getType());
    userSetRequest.setName(getName());
    userSetRequest.setOverwrite(isOverwrite());
    userSetRequest.setAccessControlEntries(getAccessControlEntries());

    PasswordGenerationParameters passwordParameters = new PasswordGenerationParameters();
    PasswordGenerationParameters usernameParameters = new PasswordGenerationParameters();
    usernameParameters.setExcludeNumber(true);
    usernameParameters.setLength(20);

    User user = generatorService.generateUser(passwordParameters, usernameParameters);
    UserSetRequestFields userSetRequestFields = new UserSetRequestFields();
    userSetRequestFields.setUsername(user.getUsername());
    userSetRequestFields.setPassword(user.getPassword());

    userSetRequest.setUserSetRequestFields(userSetRequestFields);

    return userSetRequest;
  }

  public String getGenerationParameters() {
    return generationParameters;
  }

  public void setGenerationParameters(String generationParameters) {
    this.generationParameters = generationParameters;
  }
}

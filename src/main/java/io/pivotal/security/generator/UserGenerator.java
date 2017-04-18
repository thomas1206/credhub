package io.pivotal.security.generator;

import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.secret.Password;
import io.pivotal.security.secret.User;
import org.springframework.stereotype.Component;

@Component
public class UserGenerator {

  private PassayStringSecretGenerator stringGenerator;

  public UserGenerator(PassayStringSecretGenerator stringGenerator) {
    this.stringGenerator = stringGenerator;
  }

  public User generateSecret(PasswordGenerationParameters passwordParameters, PasswordGenerationParameters usernameParameters) {
    Password password = stringGenerator.generateSecret(passwordParameters);

    Password user = stringGenerator.generateSecret(usernameParameters);

    return new User(user.getPassword(), password.getPassword());
  }
}

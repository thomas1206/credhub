package io.pivotal.security.request;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;

public class PasswordGenerateRequest extends BaseSecretGenerateRequest{
  @Override
  public NamedSecret createNewVersion(NamedSecret existing, String name, Encryptor encryptor) {
    return null;
  }
}

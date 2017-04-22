package io.pivotal.security.domain;

import io.pivotal.security.entity.PasswordCredentialData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.StringGenerationParameters;

import java.util.ArrayList;
import java.util.List;

public class PasswordCredential extends Credential<PasswordCredential> {

  private PasswordCredentialData delegate;
  private String password;
  private StringGenerationParameters generationParameters;

  public PasswordCredential(PasswordCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public PasswordCredential(String name) {
    this(new PasswordCredentialData(name));
  }

  public PasswordCredential() {
    this(new PasswordCredentialData());
  }

  public static PasswordCredential createNewVersion(
      PasswordCredential existing,
      String name,
      String password,
      StringGenerationParameters generationParameters,
      List<AccessControlEntry> accessControlEntries) {
    PasswordCredential credential;

    if (existing == null) {
      credential = new PasswordCredential(name);
    } else {
      credential = new PasswordCredential();
      credential.copyNameReferenceFrom(existing);
    }

    if (accessControlEntries == null) {
      accessControlEntries = new ArrayList<>();
    }

    credential.setAccessControlList(accessControlEntries);

    credential.setPasswordAndGenerationParameters(password, generationParameters);
    return credential;
  }

  public String getPassword() {
    return password;
  }

  public PasswordCredential setPassword(String password) {
    this.password = password;
    return this;
  }

  public PasswordCredential setGenerationParameters(StringGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
    return this;
  }

  public PasswordCredential setPasswordAndGenerationParameters(String password,
                                                               StringGenerationParameters generationParameters) {
    setPassword(password);
    setGenerationParameters(generationParameters);

    return this;
  }

  public StringGenerationParameters getGenerationParameters() {
    return generationParameters;
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  public void rotate() {
    String decryptedPassword = this.getPassword();
    StringGenerationParameters decryptedGenerationParameters = this.getGenerationParameters();
    this.setPasswordAndGenerationParameters(decryptedPassword, decryptedGenerationParameters);
  }
}

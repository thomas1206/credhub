package io.pivotal.security.domain;

import io.pivotal.security.credential.User;
import io.pivotal.security.entity.UserCredentialData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.Encryption;

import java.util.List;

public class UserCredential extends Credential<UserCredential> {
  private final UserCredentialData delegate;
  private String password;

  public static UserCredential createNewVersion(
      UserCredential existing,
      String name,
      User userValue,
      List<AccessControlEntry> accessControlEntries) {
    UserCredential credential;
    if (existing == null) {
      credential = new UserCredential(name);
    } else {
      credential = new UserCredential();
      credential.copyNameReferenceFrom(existing);
    }

    credential.setUsername(userValue.getUsername());
    credential.setPassword(userValue.getPassword());

    credential.setAccessControlList(accessControlEntries);

    return credential;
  }

  public UserCredential() {
    this(new UserCredentialData());
  }

  public UserCredential(UserCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public UserCredential(String name) {
    this(new UserCredentialData(name));
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  @Override
  public void rotate() {
    String decryptedPassword = getPassword();
    setPassword(decryptedPassword);
  }

  public UserCredential setPassword(String password) {
    this.password = password;
    return this;
  }

  public String getPassword() {
    return password;
  }

  public UserCredential setUsername(String username) {
    delegate.setUsername(username);
    return this;
  }

  public String getUsername() {
    return delegate.getUsername();
  }
}

package io.pivotal.security.domain;

import io.pivotal.security.entity.ValueCredentialData;
import io.pivotal.security.request.AccessControlEntry;

import java.util.List;

public class ValueCredential extends Credential<ValueCredential> {

  private ValueCredentialData delegate;
  private String value;

  public ValueCredential(ValueCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public ValueCredential(String name) {
    this(new ValueCredentialData(name));
  }

  public ValueCredential() {
    this(new ValueCredentialData());
  }

  public static ValueCredential createNewVersion(ValueCredential existing, String name,
                                                 String value, Encryptor encryptor, List<AccessControlEntry> accessControlEntries) {
    ValueCredential credential;

    if (existing == null) {
      credential = new ValueCredential(name);
    } else {
      credential = new ValueCredential();
      credential.copyNameReferenceFrom(existing);
    }

    credential.setAccessControlList(accessControlEntries);
    credential.setEncryptor(encryptor);
    credential.setValue(value);
    return credential;
  }

  public String getValue() {
    return value;
  }

  public ValueCredential setValue(String value) {
    this.value = value;
    return this;
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }


  public void rotate() {
    String decryptedValue = this.getValue();
    this.setValue(decryptedValue);
  }

}

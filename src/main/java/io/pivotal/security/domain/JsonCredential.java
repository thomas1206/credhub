package io.pivotal.security.domain;

import io.pivotal.security.entity.JsonCredentialData;
import io.pivotal.security.request.AccessControlEntry;

import java.util.List;
import java.util.Map;

public class JsonCredential extends Credential<JsonCredential> {

  private final JsonCredentialData delegate;
  private Map<String, Object> value;

  public JsonCredential() {
    this(new JsonCredentialData());
  }

  public JsonCredential(JsonCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public JsonCredential(String name) {
    this(new JsonCredentialData(name));
  }

  public static JsonCredential createNewVersion(
      JsonCredential existing,
      String name,
      Map<String, Object> value,
      Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries
  ) {
    JsonCredential credential;

    if (existing == null) {
      credential = new JsonCredential(name);
    } else {
      credential = new JsonCredential();
      credential.copyNameReferenceFrom(existing);
    }

    credential.setAccessControlList(accessControlEntries);
    credential.setEncryptor(encryptor);
    credential.setValue(value);

    return credential;
  }


  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  @Override
  public void rotate() {
    Map<String, Object> value = this.getValue();
    this.setValue(value);
  }

  public Map<String, Object> getValue() {
    return value;
  }

  public JsonCredential setValue(Map<String, Object> value) {
    this.value = value;
    return this;
  }
}

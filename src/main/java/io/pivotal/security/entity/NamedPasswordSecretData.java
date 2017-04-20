package io.pivotal.security.entity;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

@Entity
@DiscriminatorValue(NamedPasswordSecretData.SECRET_TYPE)
public class NamedPasswordSecretData extends NamedSecretData<NamedPasswordSecretData> {
  static final String SECRET_TYPE = "password";

  @SuppressWarnings("unused")
  public NamedPasswordSecretData() {
  }

  public NamedPasswordSecretData(String name) {
    super(name);
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }
}

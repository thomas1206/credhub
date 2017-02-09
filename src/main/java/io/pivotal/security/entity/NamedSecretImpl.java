package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;

public class NamedSecretImpl extends NamedSecretData<NamedSecretImpl> {
  @Override
  public SecretKind getKind() {
    return null;
  }

  @Override
  public String getSecretType() {
    return null;
  }

  @Override
  void copyIntoImpl(NamedSecretImpl copy) {
  }
}

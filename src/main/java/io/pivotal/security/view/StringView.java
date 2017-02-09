package io.pivotal.security.view;

import io.pivotal.security.entity.NamedStringSecretData;

class StringView extends SecretView {
  StringView(NamedStringSecretData namedStringSecret) {
    super(
        namedStringSecret.getVersionCreatedAt(),
        namedStringSecret.getUuid(),
        namedStringSecret.getName(),
        namedStringSecret.getSecretType(),
        namedStringSecret.getValue()
    );
  }
}

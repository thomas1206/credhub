package io.pivotal.security.view;

import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.secret.SshKey;

class SshView extends SecretView {
  SshView(NamedSshSecretData namedSshSecret) {
    super(
        namedSshSecret.getVersionCreatedAt(),
        namedSshSecret.getUuid(),
        namedSshSecret.getName(),
        namedSshSecret.getSecretType(),
        new SshKey(namedSshSecret.getPublicKey(), namedSshSecret.getPrivateKey())
    );
  }
}

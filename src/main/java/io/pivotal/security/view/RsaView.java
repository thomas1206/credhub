package io.pivotal.security.view;

import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.secret.RsaKey;

public class RsaView extends SecretView {
  RsaView(NamedRsaSecretData namedRsaSecret) {
    super(
        namedRsaSecret.getVersionCreatedAt(),
        namedRsaSecret.getUuid(),
        namedRsaSecret.getName(),
        namedRsaSecret.getSecretType(),
        new RsaKey(namedRsaSecret.getPublicKey(), namedRsaSecret.getPrivateKey())
    );
  }
}

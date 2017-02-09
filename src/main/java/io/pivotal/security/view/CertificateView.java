package io.pivotal.security.view;

import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.secret.Certificate;

class CertificateView extends SecretView {
  CertificateView(NamedCertificateSecretData namedCertificateSecret) {
    super(
        namedCertificateSecret.getVersionCreatedAt(),
        namedCertificateSecret.getUuid(),
        namedCertificateSecret.getName(),
        namedCertificateSecret.getSecretType(),
        new Certificate(namedCertificateSecret.getCa(), namedCertificateSecret.getCertificate(), namedCertificateSecret.getPrivateKey())
    );
  }
}

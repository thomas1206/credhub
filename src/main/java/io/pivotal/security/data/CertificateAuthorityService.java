package io.pivotal.security.data;

import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.view.ParameterizedValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateAuthorityService {
  private final SecretDataService secretDataService;

  @Autowired
  public CertificateAuthorityService(SecretDataService secretDataService) {
    this.secretDataService = secretDataService;
  }

  public Certificate findMostRecent(String caName) throws ParameterizedValidationException {
    NamedCertificateSecretData namedCertificateSecret = (NamedCertificateSecretData) secretDataService.findMostRecent(caName);
    if (namedCertificateSecret != null) {
      return new Certificate(null, namedCertificateSecret.getCertificate(), namedCertificateSecret.getPrivateKey());
    }

    throw getValidationError(caName);
  }

  private ParameterizedValidationException getValidationError(String caName) {
    if ("default".equals(caName)) {
      throw new ParameterizedValidationException("error.default_ca_required");
    }
    throw new ParameterizedValidationException("error.ca_not_found");
  }
}

package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.CertificateGenerateRequest;
import io.pivotal.security.util.CertificateReader;

import static org.apache.commons.lang3.StringUtils.isEmpty;

public class CertificateCredentialRegeneratable implements Regeneratable<CertificateCredential> {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(CertificateCredential certificateCredential) {
    CertificateReader reader = new CertificateReader(certificateCredential.getCertificate());

    if (!reader.isValid() || (isEmpty(certificateCredential.getCaName()) && !reader.isSelfSigned())) {
      throw new ParameterizedValidationException(
          "error.cannot_regenerate_non_generated_certificate");
    }

    CertificateParameters certificateParameters = new CertificateParameters(reader,
        certificateCredential.getCaName());

    CertificateGenerateRequest generateRequest = new CertificateGenerateRequest();
    generateRequest.setName(certificateCredential.getName());
    generateRequest.setType(certificateCredential.getCredentialType());
    generateRequest.setCertificateParameters(certificateParameters);
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}

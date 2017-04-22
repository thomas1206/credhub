package io.pivotal.security.domain;

import io.pivotal.security.credential.Certificate;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.request.CertificateSetRequest;
import io.pivotal.security.request.PasswordSetRequest;

public class CredentialFactory {
  public static Credential createNewVersion(
      Credential existing,
      BaseCredentialSetRequest requestBody
  ) {
    if (requestBody instanceof CertificateSetRequest) {
      return createCertificateCredential(
          (CertificateCredential) existing,
          ((CertificateSetRequest) requestBody));
    } else if (requestBody instanceof PasswordSetRequest) {
      return createPasswordCredential(
          (PasswordCredential) existing,
          ((PasswordSetRequest) requestBody));
    }
    return null;
  }

  private static PasswordCredential createPasswordCredential(
      PasswordCredential existing,
      PasswordSetRequest requestBody
  ) {
    PasswordCredential credential;

    if (existing == null) {
      credential = new PasswordCredential(requestBody.getName());
    } else {
      credential = new PasswordCredential();
      credential.copyNameReferenceFrom(existing);
    }

    credential.setAccessControlList(requestBody.getAccessControlEntries());
    credential.setPassword(requestBody.getPassword());
    credential.setGenerationParameters(requestBody.getGenerationParameters());

    return credential;
  }

  private static CertificateCredential createCertificateCredential(
      CertificateCredential existing,
      CertificateSetRequest requestBody
  ) {
    CertificateCredential credential;

    if (existing == null) {
      credential = new CertificateCredential(requestBody.getName());
    } else {
      credential = new CertificateCredential();
      credential.copyNameReferenceFrom(existing);
    }

    credential.setAccessControlList(requestBody.getAccessControlEntries());

    final Certificate certificateValue = requestBody.getCertificateValue();
    credential.setPrivateKey(certificateValue.getPrivateKey());
    credential.setCertificate(certificateValue.getCertificate());
    credential.setCa(certificateValue.getCa());
    credential.setCaName(certificateValue.getCaName());

    return credential;
  }
}

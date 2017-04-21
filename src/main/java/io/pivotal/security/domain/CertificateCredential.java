package io.pivotal.security.domain;

import io.pivotal.security.credential.Certificate;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.Encryption;

import java.util.List;

public class CertificateCredential extends Credential<CertificateCredential> {

  private CertificateCredentialData delegate;
  private String privateKey;

  public CertificateCredential(CertificateCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public CertificateCredential(String name) {
    this(new CertificateCredentialData(name));
  }

  public CertificateCredential() {
    this(new CertificateCredentialData());
  }

  public static CertificateCredential createNewVersion(
      CertificateCredential existing,
      String name,
      Certificate certificateValue,
      Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries
  ) {
    CertificateCredential credential;

    if (existing == null) {
      credential = new CertificateCredential(name);
    } else {
      credential = new CertificateCredential();
      credential.copyNameReferenceFrom(existing);
      credential.setCaName(existing.getCaName());
    }

    credential.setAccessControlList(accessControlEntries);

    credential.setPrivateKey(certificateValue.getPrivateKey());
    credential.setCertificate(certificateValue.getCertificate());
    credential.setCa(certificateValue.getCa());
    credential.setCaName(certificateValue.getCaName());
    return credential;
  }

  public String getCa() {
    return delegate.getCa();
  }

  public CertificateCredential setCa(String ca) {
    delegate.setCa(ca);
    return this;
  }

  public String getCertificate() {
    return delegate.getCertificate();
  }

  public CertificateCredential setCertificate(String certificate) {
    delegate.setCertificate(certificate);
    return this;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public CertificateCredential setPrivateKey(String privateKey) {
    this.privateKey = privateKey;
    return this;
  }

  public String getCaName() {
    return delegate.getCaName();
  }

  public CertificateCredential setCaName(String caName) {
    delegate.setCaName(caName);
    return this;
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  public void rotate() {
    String decryptedPrivateKey = this.getPrivateKey();
    this.setPrivateKey(decryptedPrivateKey);
  }
}

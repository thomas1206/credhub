package io.pivotal.security.generator;

import io.pivotal.security.credential.Certificate;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.util.CertificateFormatter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

@Component
public class CertificateGenerator implements
    CredentialGenerator<CertificateParameters, Certificate> {

  private final LibcryptoRsaKeyPairGenerator keyGenerator;
  private final SignedCertificateGenerator signedCertificateGenerator;
  private final CertificateAuthorityService certificateAuthorityService;
  private final BouncyCastleProvider provider;


  @Autowired
  public CertificateGenerator(
      LibcryptoRsaKeyPairGenerator keyGenerator,
      SignedCertificateGenerator signedCertificateGenerator,
      CertificateAuthorityService certificateAuthorityService,
      BouncyCastleProvider provider) {
    this.keyGenerator = keyGenerator;
    this.signedCertificateGenerator = signedCertificateGenerator;
    this.certificateAuthorityService = certificateAuthorityService;
    this.provider = provider;
  }

  @Override
  public Certificate generateCredential(CertificateParameters params) {
    try{
    KeyPair keyPair = keyGenerator.generateKeyPair(params.getKeyLength());

    if (params.isSelfSigned()) {
      X509Certificate cert = signedCertificateGenerator.getSelfSigned(keyPair, params);
      String certPem = CertificateFormatter.pemOf(cert);
      String privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
      return new Certificate(null, certPem, privatePem);
    } else {
      Certificate ca = certificateAuthorityService.findMostRecent(params.getCaName());

      String caCertificate = ca.getPublicKeyCertificate();
      X509Certificate cert = signedCertificateGenerator
          .getSignedByIssuer(keyPair, params, ca);

        String certPem = CertificateFormatter.pemOf(cert);
        String privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
        return new Certificate(caCertificate, certPem, privatePem);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}

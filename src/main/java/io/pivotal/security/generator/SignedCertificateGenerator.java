package io.pivotal.security.generator;

import io.pivotal.security.domain.CertificateParameters;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cryptacular.EncodingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.cryptacular.x509.ExtensionType.SubjectKeyIdentifier;

@Component
public class SignedCertificateGenerator {

  private final DateTimeProvider timeProvider;
  private final RandomSerialNumberGenerator serialNumberGenerator;
  private final BouncyCastleProvider provider;
  private final X509ExtensionUtils x509ExtensionUtils;

  @Autowired
  SignedCertificateGenerator(
      DateTimeProvider timeProvider,
      RandomSerialNumberGenerator serialNumberGenerator,
      BouncyCastleProvider provider,
      X509ExtensionUtils x509ExtensionUtils
  ) throws Exception {
    this.timeProvider = timeProvider;
    this.serialNumberGenerator = serialNumberGenerator;
    this.provider = provider;
    this.x509ExtensionUtils = x509ExtensionUtils;
  }

  X509Certificate getSelfSigned(KeyPair keyPair, CertificateParameters params)
      throws Exception {
    return getSignedByIssuer(params.getX500Name(), keyPair.getPrivate(), keyPair, params, null);
  }

  X509Certificate getSignedByIssuer(
      X500Name issuerDn,
      PrivateKey issuerKey,
      KeyPair keyPair,
      CertificateParameters params, X509Certificate caCertificate) throws Exception {
    Instant now = timeProvider.getNow().toInstant();
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
        .getInstance(keyPair.getPublic().getEncoded());

    final X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
        issuerDn,
        serialNumberGenerator.generate(),
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(params.getDuration()))),
        params.getX500Name(),
        publicKeyInfo
    );

    AuthorityKeyIdentifier authorityKeyIdentifier = null;

    if (caCertificate != null) {
      ASN1Encodable subjectKeyIdentifier = extractSubjectKeyIdentifier(caCertificate);
      if (subjectKeyIdentifier != null) {
        authorityKeyIdentifier = x509ExtensionUtils
            .createAuthorityKeyIdentifier(SubjectPublicKeyInfo
                .getInstance(caCertificate.getPublicKey().getEncoded()));
      }
    } else {
      authorityKeyIdentifier = x509ExtensionUtils.createAuthorityKeyIdentifier(publicKeyInfo);
    }

    certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
        x509ExtensionUtils.createSubjectKeyIdentifier(publicKeyInfo));

    certificateBuilder
        .addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);

    if (params.getAlternativeNames() != null) {
      certificateBuilder
          .addExtension(Extension.subjectAlternativeName, false, params.getAlternativeNames());
    }

    if (params.getKeyUsage() != null) {
      certificateBuilder.addExtension(Extension.keyUsage, true, params.getKeyUsage());
    }

    if (params.getExtendedKeyUsage() != null) {
      certificateBuilder
          .addExtension(Extension.extendedKeyUsage, false, params.getExtendedKeyUsage());
    }

    certificateBuilder
        .addExtension(Extension.basicConstraints, true, new BasicConstraints(params.isCa()));

    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider(provider)
        .build(issuerKey);

    X509CertificateHolder holder = certificateBuilder.build(contentSigner);

    return new JcaX509CertificateConverter().setProvider(provider).getCertificate(holder);
  }

  private ASN1Encodable extractSubjectKeyIdentifier(X509Certificate caCertificate) {
    byte[] data = caCertificate.getExtensionValue(SubjectKeyIdentifier.getOid());
    if (data == null) {
      return null;
    }
    try {
      ASN1Encodable der = ASN1Primitive.fromByteArray(data);
      if (der instanceof ASN1OctetString) {
        // Strip off octet string "wrapper"
        data = ((ASN1OctetString) der).getOctets();
        der = ASN1Primitive.fromByteArray(data);
      }
      return der;
    } catch (Exception e) {
      throw new EncodingException("ASN.1 parse error", e);
    }
  }
}

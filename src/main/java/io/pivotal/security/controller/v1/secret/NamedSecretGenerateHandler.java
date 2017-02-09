package io.pivotal.security.controller.v1.secret;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.entity.*;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.RsaGeneratorRequestTranslator;
import io.pivotal.security.mapper.SshGeneratorRequestTranslator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretKind;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;

@Component
class NamedSecretGenerateHandler implements SecretKindMappingFactory {

  @Autowired
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Autowired
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Autowired
  SshGeneratorRequestTranslator sshGeneratorRequestTranslator;

  @Autowired
  RsaGeneratorRequestTranslator rsaGeneratorRequestTranslator;

  @Override
  public SecretKind.CheckedMapping<NamedSecretData, NoSuchAlgorithmException> make(String secretPath, DocumentContext parsedRequest) {
    return new SecretKind.CheckedMapping<NamedSecretData, NoSuchAlgorithmException>() {
      @Override
      public NamedSecretData value(NamedSecretData namedSecret) {
        throw new ParameterizedValidationException("error.invalid_generate_type");
      }

      @Override
      public NamedSecretData password(NamedSecretData namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedPasswordSecretData) namedSecret, NamedPasswordSecretData::new, secretPath, passwordGeneratorRequestTranslator, parsedRequest);
      }

      @Override
      public NamedSecretData certificate(NamedSecretData namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedCertificateSecretData) namedSecret, NamedCertificateSecretData::new, secretPath, certificateGeneratorRequestTranslator, parsedRequest);
      }

      @Override
      public NamedSecretData ssh(NamedSecretData namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedSshSecretData) namedSecret, NamedSshSecretData::new, secretPath, sshGeneratorRequestTranslator, parsedRequest);
      }

      @Override
      public NamedSecretData rsa(NamedSecretData namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedRsaSecretData) namedSecret, NamedRsaSecretData::new, secretPath, rsaGeneratorRequestTranslator, parsedRequest);
      }
    };
  }
}

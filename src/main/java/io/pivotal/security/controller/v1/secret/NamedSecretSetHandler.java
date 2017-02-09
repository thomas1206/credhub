package io.pivotal.security.controller.v1.secret;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.RsaSshSetRequestTranslator;
import io.pivotal.security.mapper.StringSetRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;

@Component
class NamedSecretSetHandler implements SecretKindMappingFactory {

  @Autowired
  StringSetRequestTranslator stringSetRequestTranslator;

  @Autowired
  CertificateSetRequestTranslator certificateSetRequestTranslator;

  @Autowired
  RsaSshSetRequestTranslator rsaSshSetRequestTranslator;

  @Override
  public SecretKind.CheckedMapping<NamedSecretData, NoSuchAlgorithmException> make(String secretPath, DocumentContext parsedRequest) {
    return new SecretKind.CheckedMapping<NamedSecretData, NoSuchAlgorithmException>() {
      @Override
      public NamedSecretData value(NamedSecretData namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret(null, NamedValueSecretData::new, secretPath, stringSetRequestTranslator, parsedRequest);
      }

      @Override
      public NamedSecretData password(NamedSecretData namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret(null, NamedPasswordSecretData::new, secretPath, stringSetRequestTranslator, parsedRequest);
      }

      @Override
      public NamedSecretData certificate(NamedSecretData namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret(null, NamedCertificateSecretData::new, secretPath, certificateSetRequestTranslator, parsedRequest);
      }

      @Override
      public NamedSecretData ssh(NamedSecretData namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret(null, NamedSshSecretData::new, secretPath, rsaSshSetRequestTranslator, parsedRequest);
      }

      @Override
      public NamedSecretData rsa(NamedSecretData namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret(null, NamedRsaSecretData::new, secretPath, rsaSshSetRequestTranslator, parsedRequest);
      }
    };
  }
}

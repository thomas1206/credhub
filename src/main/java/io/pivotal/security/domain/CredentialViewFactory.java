package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.entity.CredentialData;
import io.pivotal.security.entity.JsonCredentialData;
import io.pivotal.security.entity.PasswordCredentialData;
import io.pivotal.security.entity.RsaCredentialData;
import io.pivotal.security.entity.SshCredentialData;
import io.pivotal.security.entity.UserCredentialData;
import io.pivotal.security.entity.ValueCredentialData;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.Encryption;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class CredentialViewFactory {
  private final Encryptor encryptor;
  private final ObjectMapper objectMapper;

  @Autowired
  CredentialViewFactory(Encryptor encryptor) {
    this.encryptor = encryptor;
    this.objectMapper = new ObjectMapper();
  }

  public Credential makeCredentialFromEntity(CredentialData credentialData) {
    if (credentialData == null) {
      return null;
    }

    final Encryption encryption = new Encryption(credentialData.getEncryptionKeyUuid(), credentialData.getEncryptedValue(), credentialData.getNonce());
    final String decryptedValue = encryptor.decrypt(encryption);

    if (credentialData instanceof CertificateCredentialData) {
      return makeCertificateCredential((CertificateCredentialData) credentialData, decryptedValue);
    } else if (credentialData instanceof PasswordCredentialData) {
      return makePasswordCredential(credentialData, decryptedValue);
    } else if (credentialData instanceof RsaCredentialData) {
      return makeRsaCredential((RsaCredentialData) credentialData, decryptedValue);
    } else if (credentialData instanceof SshCredentialData) {
      return makeSshCredential((SshCredentialData) credentialData, decryptedValue);
    } else if (credentialData instanceof ValueCredentialData) {
      return makeValueCredential((ValueCredentialData) credentialData, decryptedValue);
    } else if (credentialData instanceof JsonCredentialData) {
      return makeJsonCredential((JsonCredentialData) credentialData, decryptedValue);
    } else if (credentialData instanceof UserCredentialData) {
      return makeUserCredential((UserCredentialData) credentialData, decryptedValue);
    } else {
      throw new RuntimeException("Unrecognized type: " + credentialData.getClass().getName());
    }
  }

  public List<Credential> makeCredentialsFromEntities(List<CredentialData> daos) {
    return daos.stream().map(this::makeCredentialFromEntity).collect(Collectors.toList());
  }

  private static Credential makeCertificateCredential(CertificateCredentialData credentialData, String decryptedValue) {
    final CertificateCredential certificateCredential = new CertificateCredential(credentialData);
    certificateCredential.setPrivateKey(decryptedValue);

    return certificateCredential;
  }

  private Credential makePasswordCredential(CredentialData credentialData, String decryptedValue) {
    final PasswordCredential passwordCredential = new PasswordCredential((PasswordCredentialData) credentialData);
    final Encryption parametersEncryption = new Encryption(
        credentialData.getEncryptionKeyUuid(),
        ((PasswordCredentialData) credentialData).getEncryptedGenerationParameters(),
        ((PasswordCredentialData) credentialData).getParametersNonce());
    final String parametersJson = encryptor.decrypt(parametersEncryption);

    if (parametersJson != null) {
      Assert.notNull(decryptedValue,
          "Password length generation parameter cannot be restored without an existing password");

      try {
        final StringGenerationParameters generationParameters = objectMapper.readValue(parametersJson, StringGenerationParameters.class);
        generationParameters.setLength(decryptedValue.length());
        passwordCredential.setPasswordAndGenerationParameters(decryptedValue, generationParameters);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    return passwordCredential;
  }

  private Credential makeRsaCredential(RsaCredentialData credentialData, String decryptedValue) {
    final RsaCredential rsaCredential = new RsaCredential(credentialData);
    rsaCredential.setPrivateKey(decryptedValue);

    return rsaCredential;
  }

  private Credential makeSshCredential(SshCredentialData credentialData, String decryptedValue) {
    final SshCredential sshCredential = new SshCredential(credentialData);
    sshCredential.setPrivateKey(decryptedValue);

    return sshCredential;
  }

  private Credential makeValueCredential(ValueCredentialData credentialData, String decryptedValue) {
    final ValueCredential valueCredential = new ValueCredential(credentialData);
    valueCredential.setValue(decryptedValue);

    return valueCredential;
  }

  private Credential makeJsonCredential(JsonCredentialData credentialData, String decryptedValue) {
    final JsonCredential jsonCredential = new JsonCredential(credentialData);

    if (decryptedValue != null) {
      try {
        jsonCredential.setValue(objectMapper.readValue(decryptedValue, Map.class));
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    return jsonCredential;
  }

  private Credential makeUserCredential(UserCredentialData credentialData, String decryptedValue) {
    final UserCredential userCredential = new UserCredential(credentialData);
    userCredential.setPassword(decryptedValue);

    return userCredential;
  }
}

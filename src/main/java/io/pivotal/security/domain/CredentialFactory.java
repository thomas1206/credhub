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
public class CredentialFactory {
  private final Encryptor encryptor;
  private final ObjectMapper objectMapper;

  @Autowired
  CredentialFactory(Encryptor encryptor) {
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
      final CertificateCredential certificateCredential = new CertificateCredential((CertificateCredentialData) credentialData);
      certificateCredential.setPrivateKey(decryptedValue);

      return certificateCredential;
    } else if (credentialData instanceof PasswordCredentialData) {
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
    } else if (credentialData instanceof RsaCredentialData) {
      final RsaCredential rsaCredential = new RsaCredential((RsaCredentialData) credentialData);
      rsaCredential.setPrivateKey(decryptedValue);

      return rsaCredential;
    } else if (credentialData instanceof SshCredentialData) {
      final SshCredential sshCredential = new SshCredential((SshCredentialData) credentialData);
      sshCredential.setPrivateKey(decryptedValue);

      return sshCredential;
    } else if (credentialData instanceof ValueCredentialData) {
      final ValueCredential valueCredential = new ValueCredential((ValueCredentialData) credentialData);
      valueCredential.setValue(decryptedValue);

      return valueCredential;
    } else if (credentialData instanceof JsonCredentialData) {
      final JsonCredential jsonCredential = new JsonCredential((JsonCredentialData) credentialData);

      if (decryptedValue != null) {
        try {
          jsonCredential.setValue(objectMapper.readValue(decryptedValue, Map.class));
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      }

      return jsonCredential;
    } else if (credentialData instanceof UserCredentialData) {
      final UserCredential userCredential = new UserCredential((UserCredentialData) credentialData);
      userCredential.setPassword(decryptedValue);

      return userCredential;
    } else {
      throw new RuntimeException("Unrecognized type: " + credentialData.getClass().getName());
    }
  }

  public List<Credential> makeCredentialsFromEntities(List<CredentialData> daos) {
    return daos.stream().map(this::makeCredentialFromEntity).collect(Collectors.toList());
  }
}

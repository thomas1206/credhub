package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.view.SecretKind;
import org.springframework.util.Assert;

import java.io.IOException;

public class NamedPasswordSecret extends NamedStringSecret<NamedPasswordSecret> {

  private NamedPasswordSecretData delegate;
  private ObjectMapper objectMapper;

  public NamedPasswordSecret(NamedPasswordSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
    objectMapper = new ObjectMapper();
  }

  public NamedPasswordSecret(String name) {
    this(new NamedPasswordSecretData(name));
  }

  public NamedPasswordSecret() {
    this(new NamedPasswordSecretData());
  }

  // todo grot
  public byte[] getEncryptedGenerationParameters() {
    return delegate.getEncryptedGenerationParameters();
  }

  // todo grot
  public NamedPasswordSecret setEncryptedGenerationParameters(byte[] encryptedGenerationParameters) {
    delegate.setEncryptedGenerationParameters(encryptedGenerationParameters);
    return this;
  }

  // todo grot
  public byte[] getParametersNonce() {
    return delegate.getParametersNonce();
  }

  // todo grot
  public NamedPasswordSecret setParametersNonce(byte[] parametersNonce) {
    delegate.setParametersNonce(parametersNonce);
    return this;
  }

  public PasswordGenerationParameters getGenerationParameters() {
    String password = getValue();
    Assert.notNull(password, "Password length generation parameter cannot be restored without an existing password");
    String json = encryptor.decrypt(delegate.getEncryptionKeyUuid(), delegate.getEncryptedGenerationParameters(), delegate.getParametersNonce());
    if (json == null) {
      return null;
    }
    try {
      return objectMapper.readValue(json, PasswordGenerationParameters.class).setLength(password.length());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public NamedPasswordSecret setPasswordAndGenerationParameters(String password, PasswordGenerationParameters generationParameters) {
    try {
      String clearTextValue = generationParameters != null ? objectMapper.writeValueAsString(generationParameters) : null;

      Encryption encryptedParameters = encryptor.encrypt(clearTextValue);
      delegate.setEncryptedGenerationParameters(encryptedParameters.encryptedValue);
      delegate.setParametersNonce(encryptedParameters.nonce);

      final Encryption encryptedPassword = encryptor.encrypt(password);
      delegate.setEncryptedValue(encryptedPassword.encryptedValue);
      delegate.setNonce(encryptedPassword.nonce);

      delegate.setEncryptionKeyUuid(encryptor.getActiveUuid());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return this;
  }

  @Override
  public void rotateToLatestEncryptionKey() {
    setPasswordAndGenerationParameters(getValue(), getGenerationParameters());
  }

  @Override
  public NamedStringSecret setValue(String value) {
    throw new UnsupportedOperationException("use setPasswordAndGenerationParameters instead");
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  @Override
  public SecretKind getKind() {
    return delegate.getKind();
  }
}

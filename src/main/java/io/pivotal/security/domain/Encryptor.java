package io.pivotal.security.domain;

import io.pivotal.security.exceptions.KeyNotFoundException;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.RetryingEncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.InvalidKeyException;
import java.util.Objects;
import java.util.UUID;

@Component
public class Encryptor {

  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private final RetryingEncryptionService encryptionService;

  @Autowired
  public Encryptor(EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
      RetryingEncryptionService encryptionService) {
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.encryptionService = encryptionService;
  }

  public Encryption encrypt(String clearTextValue) {
    try {
      final UUID activeUuid = encryptionKeyCanaryMapper.getActiveUuid();
      return clearTextValue == null
          ? new Encryption(activeUuid, new byte[]{}, new byte[]{}) :
          encryptionService.encrypt(activeUuid, clearTextValue);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public String decrypt(UUID keyUuid, byte[] encryptedValue, byte[] nonce) {
    Objects.requireNonNull(keyUuid);
    Objects.requireNonNull(encryptedValue);
    Objects.requireNonNull(nonce);

    try {
      return encryptionService.decrypt(keyUuid, encryptedValue, nonce);
    } catch (KeyNotFoundException e) {
      throw e;
    } catch (InvalidKeyException ke) {
      throw new RuntimeException(ke);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}

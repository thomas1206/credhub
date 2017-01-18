package io.pivotal.security.service;

import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_BYTES;
import static org.apache.logging.log4j.LogManager.getLogger;

@Service
public class EncryptionServiceImpl implements EncryptionService {

  private final EncryptionConfiguration encryptionConfiguration;
  private final Logger logger;

  @Autowired
  public EncryptionServiceImpl(EncryptionConfiguration encryptionConfiguration) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    this.encryptionConfiguration = encryptionConfiguration;
    this.logger = getLogger(this.getClass());
  }

  @Override
  public Encryption encrypt(String value) throws Exception {
    try {
      return tryEncrypt(value);
    } catch (Exception e) {
      logger.info("Failed to encrypt secret. Trying to log in.");
      logger.info("Exception thrown: " + e.getMessage());
      encryptionConfiguration.reconnect();
      logger.info("Reconnected to the HSM");
      return tryEncrypt(value);
    }
  }

  private Encryption tryEncrypt(String value) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    byte[] nonce = new byte[NONCE_BYTES];
    encryptionConfiguration.getSecureRandom().nextBytes(nonce);

    IvParameterSpec ivSpec = new IvParameterSpec(nonce);
    Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding", encryptionConfiguration.getProvider());
    encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionConfiguration.getKey(), ivSpec);

    byte[] encrypted = encryptionCipher.doFinal(value.getBytes(charset()));

    return new Encryption(nonce, encrypted);
  }

  @Override
  public String decrypt(byte[] nonce, byte[] encryptedValue) throws Exception {
    try {
      return tryDecrypt(nonce, encryptedValue);
    } catch (Exception e) {
      logger.info("Failed to decrypt secret. Trying to log in.");
      logger.info("Exception thrown: " + e.getMessage());
      encryptionConfiguration.reconnect();
      logger.info("Reconnected to the HSM");
      return tryDecrypt(nonce, encryptedValue);
    }
  }

  private String tryDecrypt(byte[] nonce, byte[] encryptedValue) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding", encryptionConfiguration.getProvider());
    IvParameterSpec ivSpec = new IvParameterSpec(nonce);
    decryptionCipher.init(Cipher.DECRYPT_MODE, encryptionConfiguration.getKey(), ivSpec);

    return new String(decryptionCipher.doFinal(encryptedValue), charset());
  }
}

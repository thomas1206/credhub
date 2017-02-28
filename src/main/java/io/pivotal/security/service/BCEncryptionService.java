package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dev_internal")
public class BCEncryptionService extends EncryptionService {
  private static final int ITERATION_COUNT = 10000; // ???
  private static final int KEY_SIZE = 256; // ???
  private SecureRandom secureRandom;

  private final BouncyCastleProvider provider;

  @Autowired
  public BCEncryptionService(BouncyCastleProvider provider) throws Exception {
    this.provider = provider;
    this.secureRandom = SecureRandom.getInstance("SHA1PRNG");
  }

  @Override
  SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(Cipher.getInstance(CipherTypes.GCM.toString(), provider));
  }

  @Override
  IvParameterSpec generateParameterSpec(byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  @Override
  Key createKey(EncryptionKeyMetadata encryptionKeyMetadata) {
    if (encryptionKeyMetadata.getDevKey() != null) {
      return new SecretKeySpec(DatatypeConverter.parseHexBinary(encryptionKeyMetadata.getDevKey()), 0, 16, "AES");
    } else {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      AlgorithmIdentifier identifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256);
      return new PBKDF2KeySpec(
        encryptionKeyMetadata.getEncryptionPassword().toCharArray(),
        null,
        ITERATION_COUNT,
        KEY_SIZE,
        identifier);
    }
  }
}

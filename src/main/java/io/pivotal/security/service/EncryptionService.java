package io.pivotal.security.service;

import java.nio.charset.Charset;

public interface EncryptionService {
  Encryption encrypt(String value) throws Exception;

  String decrypt(byte[] nonce, byte[] encryptedValue) throws Exception;

  default Charset charset() {
    return Charset.defaultCharset();
  }

  class Encryption {
    public final byte[] nonce;
    public final byte[] encryptedValue;

    public Encryption(byte[] nonce, byte[] encryptedValue) {
      this.nonce = nonce;
      this.encryptedValue = encryptedValue;
    }
  }
}

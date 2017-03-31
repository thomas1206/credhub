package io.pivotal.security.service;

import java.util.Objects;
import java.util.UUID;

public class Encryption {

  public final UUID canaryUuid;
  public final byte[] nonce;
  public final byte[] encryptedValue;

  public Encryption(final UUID canaryUuid, final byte[] encryptedValue, final byte[] nonce) {
    Objects.requireNonNull(canaryUuid);
    Objects.requireNonNull(encryptedValue);
    Objects.requireNonNull(nonce);

    this.canaryUuid = canaryUuid;
    this.encryptedValue = encryptedValue;
    this.nonce = nonce;
  }
}

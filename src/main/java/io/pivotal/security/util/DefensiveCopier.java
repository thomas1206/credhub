package io.pivotal.security.util;

import java.util.Arrays;

public class DefensiveCopier {
  public byte[] copyByteArray(final byte[] arrayToCopy) {
    return Arrays.copyOf(arrayToCopy, arrayToCopy.length);
  }
}
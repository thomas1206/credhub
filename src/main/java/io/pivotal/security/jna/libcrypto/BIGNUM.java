package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

public class Bignum extends Structure {

  public Pointer dp;
  public int top;
  public int dmax;
  public int neg;

  public Bignum(Pointer p) {
    super(p);
  }

  @Override
  protected List getFieldOrder() {
    return Arrays.asList("dp", "top", "dmax", "neg");
  }

  public static class ByReference extends Bignum implements Structure.ByReference {

    public ByReference(Pointer p) {
      super(p);
    }
  }
}

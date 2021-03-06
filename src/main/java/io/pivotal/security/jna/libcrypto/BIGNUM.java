package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

@SuppressWarnings("checkstyle:abbreviationaswordinname")
public class BIGNUM extends Structure {

  public Pointer dp;
  public int top;
  public int dmax;
  public int neg;

  public BIGNUM(Pointer p) {
    super(p);
  }

  @Override
  protected List getFieldOrder() {
    return Arrays.asList("dp", "top", "dmax", "neg");
  }

  public static class ByReference extends BIGNUM implements Structure.ByReference {

    public ByReference(Pointer p) {
      super(p);
    }
  }
}

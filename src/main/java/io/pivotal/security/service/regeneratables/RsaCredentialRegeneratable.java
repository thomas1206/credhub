package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.RsaGenerateRequest;

public class RsaCredentialRegeneratable implements Regeneratable<RsaCredential> {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(RsaCredential rsaCredential) {
    RsaGenerateRequest generateRequest = new RsaGenerateRequest();
    generateRequest.setName(rsaCredential.getName());
    generateRequest.setType(rsaCredential.getCredentialType());
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}

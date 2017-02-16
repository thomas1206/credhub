package io.pivotal.security.model;

public class CertificateGenerationRequest extends GenerationRequest {
  private CertificateGenerationParameters parameters;

  public CertificateGenerationParameters getParameters() {
    return parameters;
  }

  public void setParameters(CertificateGenerationParameters parameters) {
    this.parameters = parameters;
  }
}

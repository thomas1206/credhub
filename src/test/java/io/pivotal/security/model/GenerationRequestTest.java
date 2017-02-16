package io.pivotal.security.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

@RunWith(Spectrum.class)
public class GenerationRequestTest {
  {
    it("should create correct class from json based on type", () -> {
      String json = "{\"type\":\"certificate\",\"name\":\"test-name\",\"parameters\":{\"common_name\":\"my-common-name\"}}";
      GenerationRequest generationRequest = new ObjectMapper().readValue(json, GenerationRequest.class);
      CertificateGenerationParameters parameters = ((CertificateGenerationRequest) generationRequest).getParameters();
      assertThat(parameters.getCommonName(), equalTo("my-common-name"));
    });
  }
}

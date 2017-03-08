package io.pivotal.security.controller.v1.permissions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.service.AccessControlService;
import io.pivotal.security.view.AccessControlListResponse;
import org.junit.runner.RunWith;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.Errors;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
public class AccessEntryControllerTest {
  private AccessControlService accessControlService;
  private MessageSource messageSource;
  private AccessEntryController subject;

  {
    beforeEach(() -> {
      accessControlService = mock(AccessControlService.class);
      messageSource = mock(MessageSource.class);
      subject = new AccessEntryController(
          accessControlService,
          messageSource
      );
    });

    describe("/aces", () -> {
      describe("#POST", () -> {
        describe("when the request has invalid JSON", () -> {
          it("should return an error", () -> {
            AccessEntryRequest accessEntryRequest = new AccessEntryRequest(
                "test-credential-name",
                null
            );

            MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
            ObjectMapper objectMapper = new ObjectMapper()
                .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
            mappingJackson2HttpMessageConverter.setObjectMapper(objectMapper);
            MockMvc mockMvc = MockMvcBuilders.standaloneSetup(subject)
                .setMessageConverters(mappingJackson2HttpMessageConverter)
                .build();
            byte[] body = new ObjectMapper().writeValueAsBytes(accessEntryRequest);
            MockHttpServletRequestBuilder request = post("/api/v1/aces")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body);

            mockMvc.perform(request)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("foo"));
          });
        });

        describe("when the request has valid JSON", () -> {
          it("should return a response containing the new ACE", () -> {
            List<AccessControlEntry> accessControlEntries = newArrayList(new AccessControlEntry("test-actor", newArrayList("read", "write")));
            AccessEntryRequest accessEntryRequest = new AccessEntryRequest(
                "test-credential-name",
                accessControlEntries
            );
            AccessControlListResponse accessEntryResponse = new AccessControlListResponse("test-actor", accessControlEntries);
            when(accessControlService.setAccessControlEntry(accessEntryRequest))
                .thenReturn(accessEntryResponse);
            Errors errors = mock(Errors.class);
            when(errors.hasErrors()).thenReturn(false);
            ResponseEntity response = subject.setAccessControlEntry(accessEntryRequest, errors);

            assertThat(response.getStatusCode(), equalTo(HttpStatus.OK));
            assertThat(response.getBody(), equalTo(accessEntryResponse));
          });
        });
      });
    });
  }
}

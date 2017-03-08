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
import java.util.Locale;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.serialize;
import static java.util.Collections.singletonMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
public class AccessEntryControllerTest {
  private AccessControlService accessControlService;
  private MessageSource messageSource;
  private AccessEntryController subject;
  private MockMvc mockMvc;

  {
    beforeEach(() -> {
      accessControlService = mock(AccessControlService.class);
      messageSource = mock(MessageSource.class);
      subject = new AccessEntryController(
          accessControlService,
          messageSource
      );

      MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
      ObjectMapper objectMapper = new ObjectMapper()
          .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
      mappingJackson2HttpMessageConverter.setObjectMapper(objectMapper);
      mockMvc = MockMvcBuilders.standaloneSetup(subject)
          .setMessageConverters(mappingJackson2HttpMessageConverter)
          .build();
    });

    describe("/aces", () -> {
      describe("#POST", () -> {
        describe("when the request has invalid JSON", () -> {
          it("should return an error", () -> {
            when(messageSource.getMessage(eq("error.acl.missing_aces"), eq(null), any(Locale.class)))
                .thenReturn("test-error-message");

            AccessEntryRequest accessEntryRequest = new AccessEntryRequest(
                "test-credential-name",
                null
            );
            byte[] body = serialize(accessEntryRequest);
            MockHttpServletRequestBuilder request = post("/api/v1/aces")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body);

            mockMvc.perform(request)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("test-error-message"));
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

    describe("/acls", () -> {
      describe("#GET", () -> {
        describe("when there is no credential_name", () -> {
          it("should return an error", () -> {
            when(messageSource.getMessage(eq("error.resource_not_found"), eq(null), any(Locale.class)))
                .thenReturn("test-error-message");

            mockMvc.perform(get("/api/v1/acls"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("foo"));
//            ResponseEntity response = subject.getAccessControlEntry("");
//
//            assertThat(response.getStatusCode(), equalTo(BAD_REQUEST));
//            assertThat(response.getBody(), equalTo("Required String parameter 'credential_name' is not present"));
          });
        });

        describe("when there is no credential with the specified name", () -> {
          it("should return an error", () -> {
            when(messageSource.getMessage(eq("error.resource_not_found"), eq(null), any(Locale.class)))
                .thenReturn("test-error-message");
            when(accessControlService.getAccessControlEntries("test_credential_name"))
                .thenReturn(null);

            ResponseEntity response = subject.getAccessControlEntry("test_credential_name");

            assertThat(response.getStatusCode(), equalTo(NOT_FOUND));
            assertThat(response.getBody(), equalTo(singletonMap("error", "test-error-message")));
          });
        });

        describe("when the credential exists", () -> {
          it("should return the ACL for the credential", () -> {
            AccessControlListResponse accessControlListResponse = new AccessControlListResponse("test_credential_name", newArrayList());
            when(accessControlService.getAccessControlEntries("test_credential_name"))
                .thenReturn(accessControlListResponse);

            ResponseEntity response = subject.getAccessControlEntry("test_credential_name");

            assertThat(response.getStatusCode(), equalTo(OK));
            assertThat(response.getBody(), equalTo(accessControlListResponse));
          });
        });
      });
    });
  }
}

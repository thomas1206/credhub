package io.pivotal.security.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import javax.validation.ConstraintViolation;
import java.util.Set;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
public class AccessControlEntryTest {
  {
    describe("JSON serialization", () -> {
      describe("validation", () -> {
        it("should allow good JSON", () -> {
          String json = "{ \n" +
              "\"actor\": \"dan\",\n" +
              "\"operations\": [\"read\"]\n" +
              "}";
          ObjectMapper om = new ObjectMapper();
          AccessControlEntry accessControlEntry = om.readValue(json, AccessControlEntry.class);
          assertThat(accessControlEntry.getActor(), equalTo("dan"));
        });

        it("should validate presence of actor", () -> {
          String json = "{ \n" +
              "\"operations\": [\"read\"]\n" +
              "}";
          Set<ConstraintViolation<AccessControlEntry>> constraintViolations = JsonHelper.deserializeAndValidate(json, AccessControlEntry.class);
          assertThat(constraintViolations.size(), equalTo(1));
          assertThat(((ConstraintViolation) constraintViolations.toArray()[0]).getMessage(), equalTo("error.acl.missing_actor"));
        });

        describe("on operations", () -> {
          it("should validate allowed values", () -> {
            String json = "{ \n" +
                "\"actor\": \"dan\",\n" +
                "\"operations\": [\"foo\", \"read\"]\n" +
                "}";
            Set<ConstraintViolation<AccessControlEntry>> constraintViolations = JsonHelper.deserializeAndValidate(json, AccessControlEntry.class);
            assertThat(constraintViolations.size(), equalTo(1));
            assertThat(((ConstraintViolation) constraintViolations.toArray()[0]).getMessage(), equalTo("error.acl.invalid_operation"));
          });

          it("should validate on exact strings", () -> {
            String json = "{ \n" +
                "\"actor\": \"dan\",\n" +
                "\"operations\": [\"readership\"]\n" +
                "}";
            Set<ConstraintViolation<AccessControlEntry>> constraintViolations = JsonHelper.deserializeAndValidate(json, AccessControlEntry.class);
            assertThat(constraintViolations.size(), equalTo(1));
            assertThat(((ConstraintViolation) constraintViolations.toArray()[0]).getMessage(), equalTo("error.acl.invalid_operation"));
          });
        });
      });
    });
  }
}

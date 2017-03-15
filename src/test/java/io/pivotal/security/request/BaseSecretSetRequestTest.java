package io.pivotal.security.request;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserialize;
import static io.pivotal.security.helper.JsonHelper.deserializeAndValidate;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.collection.IsIterableContainingInOrder.contains;
import static org.hamcrest.core.IsEqual.equalTo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.validation.ConstraintViolation;

@RunWith(Spectrum.class)
public class BaseSecretSetRequestTest {
  {
    describe("when given valid json", () -> {
      it("should be valid", () -> {
        String json = "{" +
            "\"type\":\"value\"," +
            "\"name\":\"some-name\"," + // it thinks this name has a slash in it
            "\"value\":\"some-value\"" +
            "}";
        Set<ConstraintViolation<BaseSecretSetRequest>> violations = deserializeAndValidate(json, BaseSecretSetRequest.class);
        assertThat(violations.size(), equalTo(0));
      });

      it("should set the correct fields", () -> {
        String json = "{" +
            "\"type\":\"value\"," +
            "\"name\":\"some-name\"," +
            "\"value\":\"some-value\"" +
          "}";
        BaseSecretSetRequest secretSetRequest = deserialize(json, BaseSecretSetRequest.class);

        assertThat(secretSetRequest.getType(), equalTo("value"));
        assertThat(secretSetRequest.getName(), equalTo("some-name"));
      });

      describe("#isOverwrite", () -> {
        it("should default to false", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"" +
            "}";
          BaseSecretSetRequest secretSetRequest = deserialize(json, BaseSecretSetRequest.class);

          assertThat(secretSetRequest.isOverwrite(), equalTo(false));
        });

        it("should take the provide value if set", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
            "}";
          BaseSecretSetRequest secretSetRequest = deserialize(json, BaseSecretSetRequest.class);

          assertThat(secretSetRequest.isOverwrite(), equalTo(true));
        });
      });
    });

    describe("validation", () -> {
      describe("when name ends with a slash", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"name\":\"badname/\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name contains a double slash", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"name\":\"bad//name\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name contains a reDos attack", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"name\":\"/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/foo/com/\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.invalid_name_has_slash")));
        });
      });

      describe("when name is not set", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"type\":\"value\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });

      describe("when name is an empty string", () -> {
        it("should be invalid", () -> {
          String json = "{" +
              "\"name\":\"\"," +
              "\"type\":\"value\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          Set<ConstraintViolation<BaseSecretSetRequest>> violations = JsonHelper.deserializeAndValidate(json, BaseSecretSetRequest.class);

          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });

      describe("when type is not set", () -> {
        itThrows("should throw an JsonMappingException", JsonMappingException.class, () -> {
          String json = "{" +
              "\"name\":\"some-name\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";

          JsonHelper.deserializeChecked(json, BaseSecretSetRequest.class);
        });
      });

      describe("when type is an empty string", () -> {
        itThrows("should throw an InvalidTypeIdException", InvalidTypeIdException.class, () -> {
          String json = "{" +
              "\"name\":\"some-name\"," +
              "\"type\":\"\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";

          JsonHelper.deserializeChecked(json, BaseSecretSetRequest.class);
        });
      });

      describe("when type is unknown", () -> {
        itThrows("should throw an InvalidTypeIdException", InvalidTypeIdException.class, () -> {
          String json = "{" +
              "\"name\":\"some-name\"," +
              "\"type\":\"moose\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";

          JsonHelper.deserializeChecked(json, BaseSecretSetRequest.class);
        });
      });
    });

    describe("access control entries", () -> {
      it("defaults to an empty list if not sent in the request", () -> {
        // language=JSON
        String json = "{\n" +
            "  \"name\": \"some-name\",\n" +
            "  \"type\": \"value\",\n" +
            "  \"value\": \"some-value\",\n" +
            "  \"overwrite\": true\n" +
            "}";

        final BaseSecretSetRequest request = JsonHelper.deserialize(json, BaseSecretSetRequest.class);
        assertThat(request.getAccessControlEntries(), empty());
      });

      it("should parse access control entry included in the request", () -> {
        // language=JSON
        String json = "{\n" +
            "  \"name\": \"some-name\",\n" +
            "  \"type\": \"value\",\n" +
            "  \"value\": \"some-value\",\n" +
            "  \"overwrite\": true,\n" +
            "  \"access_control_entries\": [\n" +
            "    {\n" +
            "      \"actor\": \"some-actor\",\n" +
            "      \"operations\": [\n" +
            "        \"read\",\n" +
            "        \"write\"\n" +
            "      ]\n" +
            "    }\n" +
            "  ]\n" +
            "}";
        final BaseSecretSetRequest request = JsonHelper.deserialize(json, BaseSecretSetRequest.class);

        final List<AccessControlOperation> operations = new ArrayList<>(Arrays.asList(AccessControlOperation.READ, AccessControlOperation.WRITE));
        final List<AccessControlEntry> expectedACEs = new ArrayList<>(Arrays.asList(new AccessControlEntry("some-actor", operations)));

        assertThat(request.getAccessControlEntries(), samePropertyValuesAs(expectedACEs));
      });
    });
  }
}

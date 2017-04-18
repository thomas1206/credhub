package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.secret.User;
import io.pivotal.security.service.GeneratorService;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;

import java.util.Arrays;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class UserGenerateRequestTest {
  private GeneratorService generatorService;
  private UserGenerateRequest subject;
  private AccessControlEntry accessControlEntry;

  {
    describe("#generateSetRequest", () -> {
      beforeEach(() -> {
        generatorService = mock(GeneratorService.class);
        User user = new User("fake-user", "fake-password");
        when(generatorService.generateUser(any(PasswordGenerationParameters.class),
            any(PasswordGenerationParameters.class))).thenReturn(user);
        accessControlEntry = new AccessControlEntry("test-actor",
            Arrays.asList(READ, WRITE));
        subject = new UserGenerateRequest();
        subject.setType("user");
        subject.setName("test-name");
        subject.setAccessControlEntries(Arrays.asList(accessControlEntry));
        subject.setOverwrite(true);
      });

      it("creates set request and copies all fields from the generate request", () -> {
        BaseSecretSetRequest setRequest = subject.generateSetRequest(generatorService);

        assertThat(setRequest.getType(), equalTo("user"));
        assertThat(setRequest.getName(), equalTo("test-name"));
        assertTrue(setRequest.isOverwrite());
        assertThat(setRequest.getAccessControlEntries(), equalTo(Arrays.asList(accessControlEntry)));
        assertThat(((UserSetRequest) setRequest)
          .getUserSetRequestFields()
          .getPassword(), equalTo("fake-password"));
        assertThat(((UserSetRequest) setRequest)
          .getUserSetRequestFields()
          .getUsername(), equalTo("fake-user"));
        ArgumentCaptor<PasswordGenerationParameters> captorPassword =
            ArgumentCaptor.forClass(PasswordGenerationParameters.class);
        ArgumentCaptor<PasswordGenerationParameters> captorUserName =
            ArgumentCaptor.forClass(PasswordGenerationParameters.class);

        verify(generatorService).generateUser(captorPassword.capture(), captorUserName.capture());

        PasswordGenerationParameters passwordParameters = new PasswordGenerationParameters();

        PasswordGenerationParameters usernameParameters = new PasswordGenerationParameters();
        usernameParameters.setExcludeNumber(true);
        usernameParameters.setLength(20);

        assertThat(captorPassword.getValue(), samePropertyValuesAs(passwordParameters));
        assertThat(captorUserName.getValue(), samePropertyValuesAs(usernameParameters));
      });
    });
  }
}

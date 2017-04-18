package io.pivotal.security.generator;

import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.secret.Password;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
public class UserGeneratorTest {

  private PassayStringSecretGenerator passwordGenerator;
  private UserGenerator subject;
  private PasswordGenerationParameters passwordGenerationParameters;
  private PasswordGenerationParameters userGenerationParameters;

  @Before
  public void beforeEach() {
    passwordGenerator = mock(PassayStringSecretGenerator.class);
    subject = new UserGenerator(passwordGenerator);

    passwordGenerationParameters = new PasswordGenerationParameters();
    userGenerationParameters = new PasswordGenerationParameters();

    when(passwordGenerator.generateSecret(same(passwordGenerationParameters)))
        .thenReturn(new Password("fake-password"));
    when(passwordGenerator.generateSecret(same(userGenerationParameters)))
        .thenReturn(new Password("fake-user"));
  }

  @Test
  public void generateSecret_generatesUsernameAndPassword_withCorrect_generationParameters() {
    assertThat(subject.generateSecret(passwordGenerationParameters, userGenerationParameters).getPassword(),
        equalTo("fake-password"));
    assertThat(subject.generateSecret(passwordGenerationParameters, userGenerationParameters).getUsername(),
        equalTo("fake-user"));
  }
}
package io.pivotal.security.generator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.pivotal.security.credential.CryptSaltFactory;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.request.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
public class UserGeneratorTest {

  private UserGenerator subject;

  private StringGenerationParameters passwordParameters;

  @Before
  public void beforeEach() {
    UsernameGenerator usernameGenerator = mock(UsernameGenerator.class);
    PasswordCredentialGenerator passwordGenerator = mock(PasswordCredentialGenerator.class);
    CryptSaltFactory cryptSaltFactory = mock(CryptSaltFactory.class);

    passwordParameters = mock(StringGenerationParameters.class);

    subject = new UserGenerator(usernameGenerator, passwordGenerator, cryptSaltFactory);

    StringCredentialValue generatedUsername = new StringCredentialValue("fake-generated-username");
    StringCredentialValue generatedPassword = new StringCredentialValue("fake-generated-password");

    when(usernameGenerator.generateCredential()).thenReturn(generatedUsername);
    when(passwordGenerator.generateCredential(passwordParameters)).thenReturn(generatedPassword);
    when(cryptSaltFactory.generateSalt(generatedPassword.getStringCredential()))
        .thenReturn("fake-generated-salt");
  }

  @Test
  public void generateCredential_givenAUsernameAndPasswordParameters_generatesUserWithUsernameAndGeneratedPassword() {
    final UserCredentialValue user = subject.generateCredential("test-user", passwordParameters);

    assertThat(user.getUsername(), equalTo("test-user"));
    assertThat(user.getPassword(), equalTo("fake-generated-password"));
    assertThat(user.getSalt(), equalTo("fake-generated-salt"));
  }

  @Test
  public void generateCredential_givenNoUsernameAndPasswordParameters_generatesUserWithGeneratedUsernameAndPassword() {
    final UserCredentialValue user = subject.generateCredential(null, passwordParameters);

    assertThat(user.getUsername(), equalTo("fake-generated-username"));
    assertThat(user.getPassword(), equalTo("fake-generated-password"));
    assertThat(user.getSalt(), equalTo("fake-generated-salt"));
  }
}

package io.pivotal.security.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.entity.JsonCredentialData;
import io.pivotal.security.entity.PasswordCredentialData;
import io.pivotal.security.entity.RsaCredentialData;
import io.pivotal.security.entity.SshCredentialData;
import io.pivotal.security.entity.UserCredentialData;
import io.pivotal.security.entity.ValueCredentialData;
import io.pivotal.security.service.Encryption;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CredentialViewFactoryTest {
  private final static String CREDENTIAL_NAME = "/test/name";
  private Encryptor encryptor;
  private CredentialViewFactory subject;

  @Before
  public void setUp() {
    encryptor = mock(Encryptor.class);
    subject = new CredentialViewFactory(encryptor);
  }

  @Test
  public void makeCredentialFromEntity_givenACertificateEntity_returnsACertificate() {
    final Credential credential = subject.makeCredentialFromEntity(new CertificateCredentialData(CREDENTIAL_NAME));
    assertThat(credential, instanceOf(CertificateCredential.class));
  }

  @Test
  public void makeCredentialFromEntity_givenAPasswordEntity_returnsAPassword() {
    final Credential credential = subject.makeCredentialFromEntity(new PasswordCredentialData(CREDENTIAL_NAME));
    assertThat(credential, instanceOf(PasswordCredential.class));
  }

  @Test
  public void makeCredentialFromEntity_givenARsaEntity_returnsARsa() {
    final Credential credential = subject.makeCredentialFromEntity(new RsaCredentialData(CREDENTIAL_NAME));
    assertThat(credential, instanceOf(RsaCredential.class));
  }

  @Test
  public void makeCredentialFromEntity_givenASshEntity_returnsASsh() {
    final Credential credential = subject.makeCredentialFromEntity(new SshCredentialData(CREDENTIAL_NAME));
    assertThat(credential, instanceOf(SshCredential.class));
  }

  @Test
  public void makeCredentialFromEntity_givenAValueEntity_returnsAValue() {
    final Credential credential = subject.makeCredentialFromEntity(new ValueCredentialData(CREDENTIAL_NAME));
    assertThat(credential, instanceOf(ValueCredential.class));
  }

  @Test
  public void makeCredentialFromEntity_givenAJsonEntity_returnsAJson() {
    final Credential credential = subject.makeCredentialFromEntity(new JsonCredentialData(CREDENTIAL_NAME));
    assertThat(credential, instanceOf(JsonCredential.class));
  }

  @Test
  public void makeCredentialFromEntity_givenAUserEntity_returnsAUser() {
    final Credential credential = subject.makeCredentialFromEntity(new UserCredentialData(CREDENTIAL_NAME));
    assertThat(credential, instanceOf(UserCredential.class));
  }

  @Test
  public void makeCredentialFromEntity_givenACertificateEntity_decryptsAndSetsTheValueCorrectly() {
    final Encryption encryption = new Encryption(UUID.randomUUID(), "test-encrypted-private-key".getBytes(), "test-nonce".getBytes());
    final CertificateCredentialData credentialData = new CertificateCredentialData(CREDENTIAL_NAME);
    credentialData.setEncryptionKeyUuid(encryption.canaryUuid);
    credentialData.setEncryptedValue(encryption.encryptedValue);
    credentialData.setNonce(encryption.nonce);

    when(encryptor.decrypt(encryption)).thenReturn("test-decrypted-private-key");

    final CertificateCredential credential = (CertificateCredential) subject.makeCredentialFromEntity(credentialData);

    assertThat(credential.getPrivateKey(), equalTo("test-decrypted-private-key"));
  }

  @Test
  public void makeCredentialFromEntity_givenAPasswordEntity_decryptsAndSetsTheValueCorrectly() {
    final Encryption encryption = new Encryption(UUID.randomUUID(), "test-encrypted-password".getBytes(), "test-nonce".getBytes());
    final PasswordCredentialData credentialData = new PasswordCredentialData(CREDENTIAL_NAME);
    credentialData.setEncryptionKeyUuid(encryption.canaryUuid);
    credentialData.setEncryptedValue(encryption.encryptedValue);
    credentialData.setNonce(encryption.nonce);

    when(encryptor.decrypt(encryption)).thenReturn("test-decrypted-password");

    final PasswordCredential credential = (PasswordCredential) subject.makeCredentialFromEntity(credentialData);

    assertThat(credential.getPassword(), equalTo("test-decrypted-password"));
  }

  @Test
  public void makeCredentialFromEntity_givenARsaEntity_decryptsAndSetsTheValueCorrectly() {
    final Encryption encryption = new Encryption(UUID.randomUUID(), "test-encrypted-private-key".getBytes(), "test-nonce".getBytes());
    final RsaCredentialData credentialData = new RsaCredentialData(CREDENTIAL_NAME);
    credentialData.setEncryptionKeyUuid(encryption.canaryUuid);
    credentialData.setEncryptedValue(encryption.encryptedValue);
    credentialData.setNonce(encryption.nonce);

    when(encryptor.decrypt(encryption)).thenReturn("test-decrypted-private-key");

    final RsaCredential credential = (RsaCredential) subject.makeCredentialFromEntity(credentialData);

    assertThat(credential.getPrivateKey(), equalTo("test-decrypted-private-key"));
  }

  @Test
  public void makeCredentialFromEntity_givenASshEntity_decryptsAndSetsTheValueCorrectly() {
    final Encryption encryption = new Encryption(UUID.randomUUID(), "test-encrypted-private-key".getBytes(), "test-nonce".getBytes());
    final SshCredentialData credentialData = new SshCredentialData(CREDENTIAL_NAME);
    credentialData.setEncryptionKeyUuid(encryption.canaryUuid);
    credentialData.setEncryptedValue(encryption.encryptedValue);
    credentialData.setNonce(encryption.nonce);

    when(encryptor.decrypt(encryption)).thenReturn("test-decrypted-private-key");

    final SshCredential credential = (SshCredential) subject.makeCredentialFromEntity(credentialData);

    assertThat(credential.getPrivateKey(), equalTo("test-decrypted-private-key"));
  }

  @Test
  public void makeCredentialFromEntity_givenAValueEntity_decryptsAndSetsTheValueCorrectly() {
    final Encryption encryption = new Encryption(UUID.randomUUID(), "test-encrypted-value".getBytes(), "test-nonce".getBytes());
    final ValueCredentialData credentialData = new ValueCredentialData(CREDENTIAL_NAME);
    credentialData.setEncryptionKeyUuid(encryption.canaryUuid);
    credentialData.setEncryptedValue(encryption.encryptedValue);
    credentialData.setNonce(encryption.nonce);

    when(encryptor.decrypt(encryption)).thenReturn("test-decrypted-value");

    final ValueCredential credential = (ValueCredential) subject.makeCredentialFromEntity(credentialData);

    assertThat(credential.getValue(), equalTo("test-decrypted-value"));
  }

  @Test
  public void makeCredentialFromEntity_givenAJsonEntity_decryptsAndSetsTheValueCorrectly() throws JsonProcessingException {
    final ObjectMapper objectMapper = new ObjectMapper();
    final Map<String, Object> json = new HashMap<>();
    json.put("foo", "bar");
    final String jsonString = objectMapper.writeValueAsString(json);

    final Encryption encryption = new Encryption(UUID.randomUUID(), "test-encrypted-json".getBytes(), "test-nonce".getBytes());
    final JsonCredentialData credentialData = new JsonCredentialData(CREDENTIAL_NAME);
    credentialData.setEncryptionKeyUuid(encryption.canaryUuid);
    credentialData.setEncryptedValue(encryption.encryptedValue);
    credentialData.setNonce(encryption.nonce);

    when(encryptor.decrypt(encryption)).thenReturn(jsonString);

    final JsonCredential credential = (JsonCredential) subject.makeCredentialFromEntity(credentialData);

    assertThat(credential.getValue(), equalTo(json));
  }
}

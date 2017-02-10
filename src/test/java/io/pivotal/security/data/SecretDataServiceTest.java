package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.helper.EncryptionCanaryHelper;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.SecretView;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.data.domain.Slice;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretDataServiceTest {

  @Autowired
  SecretDataService subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  @Autowired
  SecretRepository secretRepository;

  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @SpyBean
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  private final Consumer<Long> fakeTimeSetter;
  private UUID activeCanaryUuid;
  private UUID unknownCanaryUuid;

  {
    wireAndUnwire(this, false);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      jdbcTemplate.execute("delete from secret_name");
      jdbcTemplate.execute("delete from encryption_key_canary");
      fakeTimeSetter.accept(345345L);

      activeCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService).getUuid();
      unknownCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService).getUuid();

      when(encryptionKeyCanaryMapper.getActiveUuid()).thenReturn(activeCanaryUuid);
    });

    afterEach(() -> {
      jdbcTemplate.execute("delete from secret_name");
      jdbcTemplate.execute("delete from encryption_key_canary");
    });

    describe("#save", () -> {
      it("should save a secret", () -> {
        NamedPasswordSecretData secret = new NamedPasswordSecretData("/my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        NamedSecretData savedSecret = subject.save(secret);

        assertNotNull(savedSecret);

        List<NamedPasswordSecretData> passwordSecrets = getSecretsFromDb();

        assertThat(passwordSecrets.size(), equalTo(1));
        NamedPasswordSecretData passwordSecret = passwordSecrets.get(0);
        assertThat(passwordSecret.getName(), equalTo("/my-secret"));
        assertThat(passwordSecret.getEncryptedValue(), equalTo("secret-password".getBytes()));

        // Because Java UUID doesn't let us convert from a byte[] to a type 4 UUID,
        // we need to use Hibernate to check the UUID :(
        passwordSecret = (NamedPasswordSecretData) (secretRepository.findAll().get(0));
        assertThat(passwordSecret.getUuid(), equalTo(secret.getUuid()));
      });

      it("should update a secret", () -> {
        NamedPasswordSecretData secret = new NamedPasswordSecretData("/my-secret-2");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        NamedPasswordSecretData savedSecret = subject.save(secret);
        savedSecret.setEncryptionKeyUuid(activeCanaryUuid);
        savedSecret.setEncryptedValue("irynas-ninja-skills".getBytes());

        subject.save(savedSecret);

        List<NamedPasswordSecretData> passwordSecrets = getSecretsFromDb();

        assertThat(passwordSecrets.size(), equalTo(1));
        NamedPasswordSecretData passwordSecret = passwordSecrets.get(0);
        assertThat(passwordSecret.getName(), equalTo("/my-secret-2"));
        assertThat(passwordSecret.getEncryptedValue(), equalTo("irynas-ninja-skills".getBytes()));

        passwordSecret = (NamedPasswordSecretData) (secretRepository.findAll().get(0));
        assertThat(passwordSecret.getUuid(), equalTo(secret.getUuid()));
      });

      it("should generate a uuid when creating", () -> {
        NamedSshSecretData secret = new NamedSshSecretData("/my-secret-2").setPublicKey("fake-public-key");
        NamedSshSecretData savedSecret = subject.save(secret);

        UUID generatedUuid = savedSecret.getUuid();
        assertNotNull(generatedUuid);

        savedSecret.setPublicKey("updated-fake-public-key");
        savedSecret = subject.save(savedSecret);

        assertThat(savedSecret.getUuid(), equalTo(generatedUuid));
      });

      it("should save with the leading slash", () -> {
        NamedPasswordSecretData secretWithLeadingSlash = new NamedPasswordSecretData("/my/secret");

        subject.save(secretWithLeadingSlash);

        NamedPasswordSecretData savedSecret = getSecretsFromDb().get(0);

        assertThat(savedSecret.getName(), equalTo("/my/secret"));
      });

      describe("when the secret has no encrypted value", () -> {
        it("should set the default encryption key UUID", () -> {
          NamedSshSecretData secret = new NamedSshSecretData("/my-secret").setPublicKey("fake-public-key");
          NamedSshSecretData savedSecret = subject.save(secret);

          assertThat(savedSecret.getEncryptionKeyUuid(), equalTo(activeCanaryUuid));
        });
      });
    });

    describe("#delete", () -> {
      it("should delete all secrets matching a name", () -> {
        NamedPasswordSecretData secret = new NamedPasswordSecretData("/my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        subject.save(secret);
        secret = new NamedPasswordSecretData("/my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("another password".getBytes());
        subject.save(secret);
        assertThat(getSecretsFromDb().size(), equalTo(2));

        subject.delete("/my-secret");

        assertThat(subject.findAllByName("/my-secret"), empty());
      });

      it("should be able to delete a secret ignoring case", () -> {
        NamedPasswordSecretData secret = new NamedPasswordSecretData("/my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        subject.save(secret);
        secret = new NamedPasswordSecretData("/my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("another password".getBytes());
        subject.save(secret);
        assertThat(getSecretsFromDb().size(), equalTo(2));

        subject.delete("MY-SECRET");

        assertThat(subject.findContainingName("/my-secret"), empty());
      });

      it("should cascade correctly", () -> {
        NamedPasswordSecretData secret = new NamedPasswordSecretData("test-password");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(secret);
        NamedValueSecretData namedValueSecret = new NamedValueSecretData("test-value");
        namedValueSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedValueSecret);
        NamedCertificateSecretData namedCertificateSecret = new NamedCertificateSecretData("test-certificate");
        namedCertificateSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedCertificateSecret);
        NamedSshSecretData namedSshSecret = new NamedSshSecretData("test-ssh");
        namedSshSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedSshSecret);
        NamedRsaSecretData namedRsaSecret = new NamedRsaSecretData("test-rsa");
        namedRsaSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedRsaSecret);

        assertThat(getSecretsFromDb().size(), equalTo(5));

        jdbcTemplate.execute("delete from named_secret");

        assertThat(getSecretsFromDb().size(), equalTo(0));
      });

      it("should not need a leading slash to delete a secret", () -> {
        NamedPasswordSecretData secret = new NamedPasswordSecretData("/my/secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        subject.save(secret);

        subject.delete("my/secret");

        assertThat(getSecretsFromDb().size(), equalTo(0));
      });
    });

    describe("#findMostRecent", () -> {
      beforeEach(() -> {
        NamedPasswordSecretData namedPasswordSecret1 = new NamedPasswordSecretData("/my-SECRET");
        namedPasswordSecret1.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecret1.setEncryptedValue("/my-old-password".getBytes());
        NamedPasswordSecretData namedPasswordSecret2 = new NamedPasswordSecretData("MY-SECRET");
        namedPasswordSecret2.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecret2.setEncryptedValue("/my-new-password".getBytes());
        subject.save(namedPasswordSecret1);
        fakeTimeSetter.accept(345346L); // 1 second later
        subject.save(namedPasswordSecret2);
      });

      it("returns all secrets ignoring case", () -> {
        NamedPasswordSecretData passwordSecret = (NamedPasswordSecretData) subject.findMostRecent("/my-secret");
        assertThat(passwordSecret.getName(), equalTo("/my-SECRET"));
        assertThat(passwordSecret.getEncryptedValue(), equalTo("/my-new-password".getBytes()));
      });

      it("returns all secrets ignoring the leading slash", () -> {
        NamedPasswordSecretData passwordSecret = (NamedPasswordSecretData) subject.findMostRecent("my-secret");
        assertThat(passwordSecret.getName(), equalTo("/my-SECRET"));
        assertThat(passwordSecret.getEncryptedValue(), equalTo("/my-new-password".getBytes()));
      });

      it("finds most recent based on version_created_at date, not updated_at", () -> {
        NamedCertificateSecretData firstCertificate = new NamedCertificateSecretData("/my-certificate");
        firstCertificate.setEncryptionKeyUuid(activeCanaryUuid);
        firstCertificate.setCertificate("first-certificate");

        NamedCertificateSecretData secondCertificate = new NamedCertificateSecretData("/my-certificate");
        secondCertificate.setEncryptionKeyUuid(activeCanaryUuid);
        secondCertificate.setCertificate("second-certificate");

        firstCertificate = subject.save(firstCertificate);
        fakeTimeSetter.accept(445346L);
        secondCertificate = subject.save(secondCertificate);

        NamedCertificateSecretData mostRecent = (NamedCertificateSecretData) subject.findMostRecent("/my-certificate");
        assertThat(mostRecent.getCertificate(), equalTo("second-certificate"));

        firstCertificate.setCertificate("updated-first-certificate");
        fakeTimeSetter.accept(445347L);
        subject.save(firstCertificate);

        mostRecent = (NamedCertificateSecretData) subject.findMostRecent("/my-certificate");
        assertThat(mostRecent.getCertificate(), equalTo("second-certificate"));
      });
    });

    describe("#findByUuid", () -> {
      it("should be able to find secret by uuid", () -> {
        NamedPasswordSecretData secret = new NamedPasswordSecretData("/my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        NamedPasswordSecretData savedSecret = subject.save(secret);

        assertNotNull(savedSecret.getUuid());
        NamedPasswordSecretData oneByUuid = (NamedPasswordSecretData) subject.findByUuid(savedSecret.getUuid().toString());
        assertThat(oneByUuid.getName(), equalTo("/my-secret"));
        assertThat(oneByUuid.getEncryptedValue(), equalTo("secret-password".getBytes()));
      });
    });

    describe("#findContainingName", () -> {
      String valueName = "/value.Secret";
      String passwordName = "/password/Secret";
      String certificateName = "/certif/ic/atesecret";

      beforeEach(() -> {
        fakeTimeSetter.accept(2000000000123L);
        NamedValueSecretData namedValueSecret = new NamedValueSecretData(valueName);
        namedValueSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedValueSecret);
        NamedPasswordSecretData namedPasswordSecret = new NamedPasswordSecretData("/mySe.cret");
        namedPasswordSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedValueSecret);

        fakeTimeSetter.accept(1000000000123L);
        namedPasswordSecret = new NamedPasswordSecretData(passwordName);
        namedPasswordSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedPasswordSecret);
        NamedCertificateSecretData namedCertificateSecret = new NamedCertificateSecretData("/myseecret");
        namedCertificateSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedCertificateSecret);

        fakeTimeSetter.accept(3000000000123L);
        namedCertificateSecret = new NamedCertificateSecretData(certificateName);
        namedCertificateSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedCertificateSecret);
      });

      it("returns secrets in reverse chronological order", () -> {
        assertThat(subject.findContainingName("SECRET"), IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo(certificateName)),
            hasProperty("name", equalTo(valueName)),
            hasProperty("name", equalTo(passwordName))
        ));
      });

      it("should return secrets in order by version_created_at, not updated_at", () -> {
        NamedValueSecretData valueSecret = (NamedValueSecretData) subject.findMostRecent("value.Secret");
        valueSecret.setEncryptedValue("new-encrypted-value".getBytes());
        subject.save(valueSecret);
        assertThat(subject.findContainingName("SECRET"), IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo(certificateName)),
            hasProperty("name", equalTo(valueName)),
            hasProperty("name", equalTo(passwordName))
        ));
      });

      it("should return a credential, not ignoring leading slash at the start of credential name", () -> {
        fakeTimeSetter.accept(4000000000123L);
        NamedPasswordSecretData namedSecret = new NamedPasswordSecretData("/my/password/secret");
        namedSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedSecret);

        fakeTimeSetter.accept(5000000000123L);
        namedSecret = new NamedPasswordSecretData("/mypassword/secret");
        namedSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedSecret);

        List<SecretView> containingName = subject.findContainingName("/password");
        assertThat(containingName, IsIterableContainingInOrder.contains(
          hasProperty("name", equalTo("/my/password/secret")),
          hasProperty("name", equalTo(passwordName))
        ));
      });

      describe("when there are duplicate names", () -> {
        beforeEach(() -> {
          saveNamedPassword(2000000000123L, "foo/DUPLICATE");
          saveNamedPassword(1000000000123L, "foo/DUPLICATE");
          saveNamedPassword(3000000000123L, "bar/duplicate");
          saveNamedPassword(4000000000123L, "bar/duplicate");
        });

        it("should not return duplicate secret names", () -> {
          List<SecretView> secrets = subject.findContainingName("DUP");
          assertThat(secrets.size(), equalTo(2));
        });

        it("should return the most recent secret", () -> {
          List<SecretView> secrets = subject.findContainingName("DUP");

          SecretView secret = secrets.get(0);
          assertThat(secret.getName(), equalTo("/bar/duplicate"));
          assertThat(secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(4000000000123L)));

          secret = secrets.get(1);
          assertThat(secret.getName(), equalTo("/foo/DUPLICATE"));
          assertThat(secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(2000000000123L)));
        });
      });
    });

    describe("#findStartingWithPath", () -> {
      beforeEach(() -> {
        saveNamedPassword(2000000000123L, "/secret/1");
        saveNamedPassword(3000000000123L, "/Secret/2");
        saveNamedPassword(1000000000123L, "/SECRET/3");
        saveNamedPassword(1000000000123L, "/not/So/Secret");
        saveNamedPassword(1000000000123L, "/SECRETnotrailingslash");
      });

      it("should return a list of secrets in chronological order that start with a given string", () -> {
        List<SecretView> secrets = subject.findStartingWithPath("Secret/");

        assertThat(secrets.size(), equalTo(3));
        assertThat(secrets, IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo("/Secret/2")),
            hasProperty("name", equalTo("/secret/1")),
            hasProperty("name", equalTo("/SECRET/3"))
        ));
        assertThat(secrets, not(contains(hasProperty("notSoSecret"))));
      });

      it("should return secrets in order by version_created_at, not updated_at", () -> {
        NamedPasswordSecretData passwordSecret = (NamedPasswordSecretData) subject.findMostRecent("secret/1");
        passwordSecret.setEncryptedValue("new-encrypted-value".getBytes());
        subject.save(passwordSecret);
        List<SecretView> secrets = subject.findStartingWithPath("Secret/");
        assertThat(secrets, IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo("/Secret/2")),
            hasProperty("name", equalTo("/secret/1")),
            hasProperty("name", equalTo("/SECRET/3"))
        ));
      });

      describe("when there are duplicate names", () -> {
        beforeEach(() -> {
          saveNamedPassword(2000000000123L, "/DupSecret/1");
          saveNamedPassword(3000000000123L, "/DupSecret/1");
          saveNamedPassword(1000000000123L, "/DupSecret/1");
        });

        it("should not return duplicate secret names", () -> {
          List<SecretView> secrets = subject.findStartingWithPath("/dupsecret/");
          assertThat(secrets.size(), equalTo(1));
        });

        it("should return the most recent secret", () -> {
          List<SecretView> secrets = subject.findStartingWithPath("/dupsecret/");
          SecretView secret = secrets.get(0);
          assertThat(secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(3000000000123L)));
        });
      });

      it("should ignore a leading slash", () -> {
        List<SecretView> secrets = subject.findStartingWithPath("Secret");

        assertThat(secrets.size(), equalTo(3));
        assertThat(secrets, not(contains(hasProperty("name", equalTo("/not/So/Secret")))));
      });

      describe("when the path does not have a trailing slash", () -> {
        it("should append an ending slash", () -> {
          List<SecretView> secrets = subject.findStartingWithPath("Secret");

          assertThat(secrets.size(), equalTo(3));
          assertThat(secrets, not(contains(hasProperty("name", equalTo("/SECRETnotrailingslash")))));
        });
      });
    });

    describe("#findAllPaths", () -> {
      beforeEach(() -> {
        String valueOther = "/fubario";
        String valueName = "/value/Secret";
        String passwordName = "/password/Secret";
        String certificateName = "/certif/ic/ateSecret";
        NamedValueSecretData namedValueSecret = new NamedValueSecretData(valueOther);
        namedValueSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedValueSecret);
        namedValueSecret = new NamedValueSecretData(valueName);
        namedValueSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedValueSecret);
        NamedPasswordSecretData namedPasswordSecret = new NamedPasswordSecretData(passwordName);
        namedPasswordSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedPasswordSecret);
        NamedCertificateSecretData namedCertificateSecret = new NamedCertificateSecretData(certificateName);
        namedCertificateSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedCertificateSecret);
      });

      it("can fetches possible paths for all secrets", () -> {
        assertThat(subject.findAllPaths(), equalTo(newArrayList("/", "/certif/", "/certif/ic/", "/password/", "/value/")));
      });
    });

    describe("#findAllByName", () -> {
      describe("when there are matching secrets", () -> {
        it("finds all by name", () -> {
          NamedPasswordSecretData secret1 = saveNamedPassword(2000000000123L, "/secret1");
          NamedPasswordSecretData secret2 = saveNamedPassword(4000000000123L, "/seCret1");
          saveNamedPassword(3000000000123L, "/Secret2");

          List<NamedSecretData> secrets = subject.findAllByName("/Secret1");
          assertThat(secrets, containsInAnyOrder(hasProperty("uuid", equalTo(secret1.getUuid())), hasProperty("uuid", equalTo(secret2.getUuid()))));
        });

        it("finds all by name prepending the leading slash", () -> {
          NamedPasswordSecretData secret1 = saveNamedPassword(2000000000123L, "/secret1");
          NamedPasswordSecretData secret2 = saveNamedPassword(4000000000123L, "/secret1");

          List<NamedSecretData> secrets = subject.findAllByName("Secret1");
          assertThat(secrets, containsInAnyOrder(hasProperty("uuid", equalTo(secret1.getUuid())), hasProperty("uuid", equalTo(secret2.getUuid()))));
        });
      });

      describe("when there are no matching secrets", () -> {
        it("returns an empty list", () -> {
          assertThat(subject.findAllByName("does/NOT/exist"), empty());
        });
      });
    });

    describe("#findEncryptedWithAvailableInactiveKey", () -> {
      it("should return all versions of all secrets encrypted with a known and inactive key", () -> {
        UUID oldCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService).getUuid();

        when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys()).thenReturn(Arrays.asList(oldCanaryUuid));

        NamedPasswordSecretData secret1 = saveNamedPassword(2000000000123L, "secret", oldCanaryUuid);
        NamedPasswordSecretData secret2 = saveNamedPassword(3000000000123L, "ANOTHER", oldCanaryUuid);
        NamedPasswordSecretData secret3 = saveNamedPassword(4000000000123L, "password", oldCanaryUuid);
        NamedPasswordSecretData secret1Newer = saveNamedPassword(5000000000123L, "secret", oldCanaryUuid);

        NamedPasswordSecretData secretEncryptedWithActiveKey = saveNamedPassword(3000000000123L, "ANOTHER", activeCanaryUuid);
        NamedPasswordSecretData newerSecretEncryptedWithActiveKey = saveNamedPassword(4000000000123L, "ANOTHER", activeCanaryUuid);

        NamedPasswordSecretData secretEncryptedWithUnknownKey = saveNamedPassword(4000000000123L, "ANOTHER", unknownCanaryUuid);

        final Slice<NamedSecretData> secrets = subject.findEncryptedWithAvailableInactiveKey();
        List<UUID> secretUuids = secrets.getContent().stream().map(secret -> secret.getUuid()).collect(Collectors.toList());

        assertThat(secretUuids, not(contains(secretEncryptedWithActiveKey.getUuid())));
        assertThat(secretUuids, not(contains(newerSecretEncryptedWithActiveKey.getUuid())));

        assertThat(secretUuids, not(contains(secretEncryptedWithUnknownKey.getUuid())));

        assertThat(secretUuids, containsInAnyOrder(secret1.getUuid(), secret2.getUuid(), secret3.getUuid(), secret1Newer.getUuid()));
      });
    });
  }

  private NamedPasswordSecretData saveNamedPassword(long timeMillis, String secretName, UUID canaryUuid) {
    fakeTimeSetter.accept(timeMillis);
    NamedPasswordSecretData secretObject = new NamedPasswordSecretData(secretName);
    secretObject.setEncryptionKeyUuid(canaryUuid);
    return subject.save(secretObject);
  }

  private NamedPasswordSecretData saveNamedPassword(long timeMillis, String secretName) {
    return saveNamedPassword(timeMillis, secretName, activeCanaryUuid);
  }

  private List<NamedPasswordSecretData> getSecretsFromDb() {
    List<SecretName> names = jdbcTemplate.query("select * from secret_name", (rowSet, rowNum) -> {
      SecretName secretName = new SecretName(rowSet.getString("name"));
      secretName.setUuid(UUID.nameUUIDFromBytes(rowSet.getBytes("uuid")));
      return secretName;
    });
    return jdbcTemplate.query("select * from named_secret", (rowSet, rowNum) -> {
      NamedPasswordSecretData passwordSecret = new NamedPasswordSecretData();

      UUID secretNameUuid = UUID.nameUUIDFromBytes(rowSet.getBytes("secret_name_uuid"));
      SecretName secretName = names.stream()
          .filter(x -> x.getUuid().equals(secretNameUuid))
          .findFirst()
          .orElseThrow(() -> new RuntimeException("Failed to appropriate SecretName for NamedSecret"));

      passwordSecret.setSecretName(secretName);
      passwordSecret.setUuid(UUID.nameUUIDFromBytes(rowSet.getBytes("uuid")));
      passwordSecret.setNonce(rowSet.getBytes("nonce"));
      passwordSecret.setEncryptedValue(rowSet.getBytes("encrypted_value"));

      return passwordSecret;
    });
  }
}

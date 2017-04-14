package io.pivotal.security.data;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.core.IsEqual.equalTo;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
//@SpringBootTest(classes = CredentialManagerApp.class)
//@Transactional
@DataJpaTest
public class AccessControlDataServiceTest {

  @Autowired
  private AccessEntryRepository accessEntryRepository;

  @Autowired
  private SecretNameRepository secretNameRepository;

  @Autowired
  private JdbcTemplate jdbcTemplate;

  @Autowired
  private SecretRepository secretRepository;

  private List<AccessControlEntry> aces;

  private AccessControlDataService subject;

  @Before
  public void beforeEach() {
    subject = new AccessControlDataService(accessEntryRepository, secretNameRepository, jdbcTemplate);
  }

  @Test
  public void  getAccessControlList_givenAnExistingCredentialName_returnsAcl() {
    this.seedDatabase();
    List<AccessControlEntry> accessControlEntries = subject.getAccessControlList("/lightsaber");

    assertThat(accessControlEntries, hasSize(2));

    assertThat(accessControlEntries, containsInAnyOrder(
        allOf(hasProperty("actor", equalTo("Luke")),
            hasProperty("allowedOperations", hasItems(AccessControlOperation.WRITE))),
        allOf(hasProperty("actor", equalTo("Leia")),
            hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))))
    );
  }

  @Test(expected = EntryNotFoundException.class)
  public void getAccessControlList_givenNonExistentCredentialName_throwsException() {
    subject.getAccessControlList("/unicorn");
  }

  @Test
  public void setAccessControlEntries_givenAnExistingACE_returnsAcl() {
    seedDatabase();

    aces = singletonList(
        new AccessControlEntry("Luke", singletonList(AccessControlOperation.READ)));


    List<AccessControlEntry> response = subject.setAccessControlEntries("/lightsaber", aces);

    assertThat(response, containsInAnyOrder(
        allOf(hasProperty("actor", equalTo("Luke")),
            hasProperty("allowedOperations",
                hasItems(AccessControlOperation.READ, AccessControlOperation.WRITE))),
        allOf(hasProperty("actor", equalTo("Leia")),
            hasProperty("allowedOperations", hasItems(AccessControlOperation.READ)))));
  }

  @Test
  public void setAccessControlEntries_givenANewACE_returnsAcl() {
    secretNameRepository.save(new SecretName("lightsaber2"));
    aces = singletonList(
        new AccessControlEntry("Luke", singletonList(AccessControlOperation.READ)));

    List<AccessControlEntry> response = subject.setAccessControlEntries("lightsaber2", aces);

    assertThat(response.size(), equalTo(1));
    assertThat(response.get(0).getActor(), equalTo("Luke"));
    assertThat(response.get(0).getAllowedOperations().size(),
        equalTo(1));
    assertThat(response.get(0).getAllowedOperations(),
        hasItem(AccessControlOperation.READ));
  }

  @Test
  public void deleteAccessControlEntry_givenExistingCredentialAndActor_removesAce() {
    this.seedDatabase();
    assertThat(subject.getAccessControlList("/lightsaber"),
        containsInAnyOrder(
            allOf(hasProperty("actor", equalTo("Luke")),
                hasProperty("allowedOperations", hasItems(AccessControlOperation.WRITE))),
            allOf(hasProperty("actor", equalTo("Leia")),
                hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))))
    );

    subject.deleteAccessControlEntries("/lightsaber", "Luke");

    final List<AccessControlEntry> accessControlList = subject
        .getAccessControlList("/lightsaber");
    assertThat(accessControlList,
        not(hasItem(hasProperty("actor", equalTo("Luke")))));
    assertThat(accessControlList, contains(
        allOf(hasProperty("actor", equalTo("Leia")),
            hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))))
    );
  }

  @Test(expected = EntryNotFoundException.class)
  public void deleteAccessControlEntry_givenNonExistentCredential_throwsException() {
    subject.deleteAccessControlEntries("/some-thing-that-is-not-here", "Luke");
  }

  @Test
  public void deleteAccessControlEntry_givenNonExistentActor_doesNothing() {
    this.seedDatabase();
    subject.deleteAccessControlEntries("/lightsaber", "HelloKitty");
  }

  @Test
  public void hasAclReadPermission_whenUserHasAclRead_returnsTrue() {
    secretNameRepository.save(new SecretName("/test/credential"));
    final List<AccessControlOperation> operations = asList(AccessControlOperation.READ_ACL, AccessControlOperation.DELETE);
    final AccessControlEntry accessControlEntry = new AccessControlEntry("test-actor", operations);
    subject.setAccessControlEntries("/test/credential", singletonList(accessControlEntry));

    assertThat(subject.hasReadAclPermission("test-actor", "/test/credential"), is(true));
  }

  @Test
  public void hasAclReadPermission_whenUserHasAclRead_returnsTrueRegardlessOfCredentialNameCase() {
    secretNameRepository.save(new SecretName("/test/credential"));
    final List<AccessControlOperation> operations = asList(AccessControlOperation.READ_ACL, AccessControlOperation.DELETE);
    final AccessControlEntry accessControlEntry = new AccessControlEntry("test-actor", operations);
    subject.setAccessControlEntries("/test/credential", singletonList(accessControlEntry));

    assertThat(subject.hasReadAclPermission("test-actor", "/TEST/credential"), is(true));
  }

  @Test
  public void hasAclReadPermission_whenUserCanReadCredentialButNotAcl_returnsFalse() {
    secretNameRepository.save(new SecretName("/test/credential"));
    final List<AccessControlOperation> operations = asList(AccessControlOperation.WRITE_ACL, AccessControlOperation.DELETE);
    final AccessControlEntry accessControlEntry = new AccessControlEntry("test-actor", operations);
    subject.setAccessControlEntries("/test/credential", singletonList(accessControlEntry));

    assertThat(subject.hasReadAclPermission("test-actor", "/test/credential"), is(false));
  }

  @Test
  public void hasAclReadPermission_whenUserHasNoPermissionsForCredential_returnsFalse() {
    assertThat(subject.hasReadAclPermission("test-actor", "/test/credential"), is(false));
  }



  private void seedDatabase() {
    secretNameRepository.save(new SecretName("lightsaber"));

    subject.setAccessControlEntries(
        "lightsaber",
        singletonList(new AccessControlEntry("Luke",
            singletonList(AccessControlOperation.WRITE)))
    );

    subject.setAccessControlEntries(
        "lightsaber",
        singletonList(new AccessControlEntry("Leia",
            singletonList(AccessControlOperation.READ)))
    );
  }
}

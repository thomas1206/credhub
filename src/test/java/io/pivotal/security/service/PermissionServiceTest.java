package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.PermissionException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.test.util.ReflectionTestUtils;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.assertj.core.api.Java6Assertions.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class PermissionServiceTest {
  private static final CredentialName CREDENTIAL_NAME = new CredentialName("test-credential");

  private PermissionService subject;

  private UserContext userContext;
  private AccessControlDataService accessControlDataService;
  private SshCredential credential = mock(SshCredential.class);

  @Before
  public void beforeEach() {
    userContext = mock(UserContext.class);
    when(userContext.getAclUser()).thenReturn("test-actor");
    when(credential.getCredentialName()).thenReturn(CREDENTIAL_NAME);

    accessControlDataService = mock(AccessControlDataService.class);

    subject = new PermissionService(accessControlDataService);
  }

  @Test
  public void verifyAclReadPermission_withEnforcement_whenTheUserHasPermission_doesNothing() {
    initializeEnforcement(true);

    when(accessControlDataService.hasReadAclPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    subject.verifyAclReadPermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void verifyAclReadPermission_withEnforcement_whenTheUserDoesNotHavePermission_throwsException() {
    initializeEnforcement(true);

    when(accessControlDataService.hasReadAclPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.verifyAclReadPermission(userContext, CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (PermissionException e) {
      assertThat(e.getMessage(), equalTo("error.acl.lacks_acl_read"));
    }
  }

  @Test
  public void verifyAclReadPermission_withOutEnforcement_whenTheUserHasPermission_doesNothing() {
    initializeEnforcement(false);

    when(accessControlDataService.hasReadAclPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    subject.verifyAclReadPermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void verifyAclReadPermission_withoutEnforcement_whenTheUserDoesNotHavePermission_doesNothing() {
    initializeEnforcement(false);

    when(accessControlDataService.hasReadAclPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    subject.verifyAclReadPermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void verifyCredentialWritePermission_withEnforcement_whenTheUserHasPermission_doesNothing() {
    initializeEnforcement(true);

    when(accessControlDataService.hasCredentialWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    subject.verifyCredentialWritePermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void verifyCredentialWritePermission_withEnforcement_whenTheUserDoesNotHavePermission_throwsException() {
    initializeEnforcement(true);

    when(accessControlDataService.hasCredentialWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.verifyCredentialWritePermission(userContext, CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (PermissionException e) {
      assertThat(e.getMessage(), equalTo("error.acl.lacks_credential_write"));
    }
  }

  @Test
  public void verifyCredentialWritePermission_withOutEnforcement_whenTheUserHasPermission_doesNothing() {
    initializeEnforcement(false);

    when(accessControlDataService.hasCredentialWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    subject.verifyCredentialWritePermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void verifyCredentialWritePermission_withoutEnforcement_whenTheUserDoesNotHavePermission_doesNothing() {
    initializeEnforcement(false);

    when(accessControlDataService.hasCredentialWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    subject.verifyCredentialWritePermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void hasCredentialReadPermission_withEnforcement_whenTheUserPermission_returnsTrue() {
    initializeEnforcement(true);

    when(accessControlDataService.hasReadPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    assertTrue(subject.hasCredentialReadPermission(userContext, credential));
  }

  @Test
  public void hasCredentialReadPermission_withEnforcement_whenTheUserDoesNotHavePermission_returnsFalse() {
    initializeEnforcement(true);

    when(accessControlDataService.hasReadPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    assertFalse(subject.hasCredentialReadPermission(userContext, credential));
  }

  @Test
  public void hasCredentialReadPermission_withOutEnforcement_whenTheUserHasPermission_returnsTrue() {
    initializeEnforcement(false);

    when(accessControlDataService.hasReadPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    assertTrue(subject.hasCredentialReadPermission(userContext, credential));
  }

  @Test
  public void hasCredentialReadPermission_withoutEnforcement_whenTheUserDoesNotHavePermission_returnsTrue() {
    initializeEnforcement(false);

    when(accessControlDataService.hasReadPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    assertTrue(subject.hasCredentialReadPermission(userContext, credential));
  }

  private void initializeEnforcement(boolean enabled) {
    ReflectionTestUtils
        .setField(subject, PermissionService.class, "enforcePermissions", enabled, boolean.class);
  }
}

package io.pivotal.security.handler;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.repository.CredentialNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.AccessControlListResponse;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AccessControlHandler {
  private final PermissionService permissionService;
  private final AccessControlDataService accessControlDataService;
  private final CredentialNameRepository credentialNameRepository;

  @Autowired
  AccessControlHandler(
      PermissionService permissionService,
      AccessControlDataService accessControlDataService,
      CredentialNameRepository credentialNameRepository
  ) {
    this.permissionService = permissionService;
    this.accessControlDataService = accessControlDataService;
    this.credentialNameRepository = credentialNameRepository;
  }

  public AccessControlListResponse getAccessControlListResponse(UserContext userContext, String name) {
    try {
      final CredentialName credentialName = getCredentialName(name);

      permissionService.verifyAclReadPermission(userContext, credentialName);

      return new AccessControlListResponse(
          credentialName.getName(),
          accessControlDataService.getAccessControlList(credentialName)
      );
    } catch (PermissionException pe){
      // lack of permissions should be indistinguishable from not found.
      throw new EntryNotFoundException("error.resource_not_found");
    }
  }

  public AccessControlListResponse setAccessControlEntries(
      List<EventAuditRecordParameters> parametersList,
      String credential,
      List<AccessControlEntry> accessControlEntries
  ) {
    CredentialName credentialName = getCredentialName(credential);
    updateAccessControlEntries(parametersList, credentialName, accessControlEntries);
    return new AccessControlListResponse(credential, accessControlDataService.getAccessControlList(credentialName));
  }

  public void updateAccessControlEntries(
      List<EventAuditRecordParameters> parametersList,
      CredentialName credentialName,
      List<AccessControlEntry> accessControlEntries
  ) {
    addAuditParameters(parametersList, credentialName, accessControlEntries);

    accessControlDataService
        .setAccessControlEntries(credentialName, accessControlEntries);
  }

  public AccessControlEntry deleteAccessControlEntries(String actor, String name) {
    final CredentialName credentialName = getCredentialName(name);
    return accessControlDataService.deleteAccessControlEntries(actor, credentialName);
  }

  private CredentialName getCredentialName(String name) {
    final CredentialName credentialName = credentialNameRepository
        .findOneByNameIgnoreCase(name);

    if (credentialName == null) {
      throw new EntryNotFoundException("error.resource_not_found");
    }
    return credentialName;
  }

  private void addAuditParameters(
      List<EventAuditRecordParameters> parametersList,
      CredentialName credentialName,
      List<AccessControlEntry> accessControlEntries
  ) {
    accessControlEntries
        .stream()
        .forEach(entry -> {
          entry.getAllowedOperations()
              .stream()
              .forEach(operation -> {
                parametersList.add(new EventAuditRecordParameters(
                    AuditingOperationCode.ACL_UPDATE,
                    credentialName.getName(),
                    operation,
                    entry.getActor()));
              });
        });
  }
}

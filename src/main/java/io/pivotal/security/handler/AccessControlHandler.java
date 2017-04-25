package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.repository.CredentialNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessEntriesRequest;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.AccessControlListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

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
    AccessControlListResponse response = null;

    try {
      final CredentialName credentialName = credentialNameRepository
          .findOneByNameIgnoreCase(name);

      if (credentialName == null) {
        throw new EntryNotFoundException("error.resource_not_found");
      }

      permissionService.verifyAclReadPermission(userContext, credentialName);
      List<AccessControlEntry> accessControlList = accessControlDataService.getAccessControlList(credentialName);

      response = new AccessControlListResponse();
      response.setCredentialName(credentialName.getName());
      response.setAccessControlList(accessControlList);
    } catch (PermissionException pe){
      // lack of permissions should be indistinguishable from not found.
      throw new EntryNotFoundException("error.resource_not_found");
    }

    return response;
  }

  public AccessControlListResponse setAccessControlEntries(AccessEntriesRequest request) {
    List<AccessControlEntry> accessControlEntryList = accessControlDataService
        .setAccessControlEntries(request.getCredentialName(), request.getAccessControlEntries());

    AccessControlListResponse response = new AccessControlListResponse();
    response.setCredentialName(request.getCredentialName());
    response.setAccessControlList(accessControlEntryList);

    return response;
  }

  public void deleteAccessControlEntries(String credentialName, String actor) {
    accessControlDataService.deleteAccessControlEntries(credentialName, actor);
  }
}

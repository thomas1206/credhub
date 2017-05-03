package io.pivotal.security.preauthorization;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.request.BaseCredentialRequest;
import io.pivotal.security.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class Authorization {
  private final CredentialDataService credentialDataService;
  private final PermissionService permissionService;

  @Autowired
  public Authorization(
    CredentialDataService credentialDataService,
    PermissionService permissionService
  ) {
    this.credentialDataService = credentialDataService;
    this.permissionService = permissionService;
  }

  public boolean hasAccess(BaseCredentialRequest request, UserContext user) {
    if (credentialDataService.findMostRecent(request.getName()) != null) {
      Credential credential = credentialDataService.findMostRecent(request.getName());
        return permissionService.hasCredentialReadPermission(user, credential);
    } else {
      return true;
    }
  }
}
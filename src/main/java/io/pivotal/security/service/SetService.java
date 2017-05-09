package io.pivotal.security.service;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.CredentialFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionsEventAuditParameters;

@Service
public class SetService {

  private final CredentialDataService credentialDataService;
  private final AccessControlDataService accessControlDataService;
  private PermissionService permissionService;
  private final Encryptor encryptor;
  private final CredentialFactory credentialFactory;

  @Autowired
  public SetService(
      CredentialDataService credentialDataService,
      AccessControlDataService accessControlDataService,
      PermissionService permissionService,
      Encryptor encryptor,
      CredentialFactory credentialFactory
  ) {
    this.credentialDataService = credentialDataService;
    this.accessControlDataService = accessControlDataService;
    this.permissionService = permissionService;
    this.encryptor = encryptor;
    this.credentialFactory = credentialFactory;
  }

  public CredentialView performSet(
      UserContext userContext,
      List<EventAuditRecordParameters> parametersList,
      String credentialName,
      boolean isOverwrite,
      String type,
      StringGenerationParameters generationParameters,
      CredentialValue credentialValue,
      List<AccessControlEntry> accessControlEntries,
      AccessControlEntry currentUserAccessControlEntry) {
    Credential existingCredential = credentialDataService.findMostRecent(credentialName);

    boolean shouldWriteNewEntity = existingCredential == null || isOverwrite;

    AuditingOperationCode credentialOperationCode =
        shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    parametersList
        .add(new EventAuditRecordParameters(credentialOperationCode, credentialName));

    if (existingCredential != null) {
      permissionService
          .verifyCredentialWritePermission(userContext, existingCredential.getCredentialName());
    }

    if (existingCredential != null && !existingCredential.getCredentialType().equals(type)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }

    Credential storedCredentialVersion = existingCredential;
    if (shouldWriteNewEntity) {
      if (existingCredential == null) {
        accessControlEntries.add(currentUserAccessControlEntry);
      }

      Credential newVersion = credentialFactory.makeNewCredentialVersion(
              type,
              credentialName,
              credentialValue,
              existingCredential,
              generationParameters);
      storedCredentialVersion = credentialDataService.save(newVersion);

      accessControlDataService.saveAccessControlEntries(
          userContext.getAclUser(),
          storedCredentialVersion.getCredentialName(),
          accessControlEntries);
      parametersList.addAll(createPermissionsEventAuditParameters(
          ACL_UPDATE,
          storedCredentialVersion.getName(),
          accessControlEntries
      ));
    }

    return CredentialView.fromEntity(storedCredentialVersion);
  }
}

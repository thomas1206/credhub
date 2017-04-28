package io.pivotal.security.service;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.view.CredentialView;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SetService {
  private final Encryptor encryptor;
  private final CredentialDataService credentialDataService;

  @Autowired
  public SetService(CredentialDataService credentialDataService,
                    Encryptor encryptor
  ) {
    this.credentialDataService = credentialDataService;
    this.encryptor = encryptor;
  }

  public CredentialView performSet(
      List<EventAuditRecordParameters> parametersList,
      BaseCredentialSetRequest requestBody,
      AccessControlEntry currentUserAccessControlEntry
    ) {
    Credential existingCredential = credentialDataService.findMostRecent(requestBody.getName());

    if (existingCredential == null) { requestBody.addCurrentUser(currentUserAccessControlEntry); }

    boolean shouldWriteNewEntity = existingCredential == null || requestBody.isOverwrite();
    String credentialName = existingCredential != null ? existingCredential.getName() :
        requestBody.getName();

    parametersList.add(new EventAuditRecordParameters(
        shouldWriteNewEntity ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS,
        credentialName
    ));

    final String type = requestBody.getType();
    validateCredentialType(existingCredential, type);

    Credential storedEntity = existingCredential;
    if (shouldWriteNewEntity) {
      Credential newEntity = (Credential) requestBody.createNewVersion(existingCredential, encryptor);
      storedEntity = credentialDataService.save(newEntity);
    }
    final String currentActor = currentUserAccessControlEntry.getActor();

    currentUserAccessControlEntry
        .getAllowedOperations()
        .stream()
        .forEach(operation -> {
          parametersList.add(new EventAuditRecordParameters(ACL_UPDATE, credentialName, operation,
              currentActor));
        });

    return CredentialView.fromEntity(storedEntity);
  }

  private void validateCredentialType(Credential existingCredential, String secretType) {
    if (existingCredential != null && !existingCredential.getCredentialType().equals(secretType)) {
      throw new ParameterizedValidationException("error.type_mismatch");
    }
  }
}

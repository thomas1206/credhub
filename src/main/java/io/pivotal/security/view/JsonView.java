package io.pivotal.security.view;

import io.pivotal.security.credential.JsonCredentialValue;
import io.pivotal.security.domain.JsonCredential;

@SuppressWarnings("unused")
public class JsonView extends CredentialView {

  JsonView() {  /* Jackson */ }

  JsonView(JsonCredential jsonCredential) {
    super(
        jsonCredential.getVersionCreatedAt(),
        jsonCredential.getUuid(),
        jsonCredential.getName(),
        jsonCredential.getCredentialType(),
        new JsonCredentialValue(jsonCredential.getValue())
    );
  }
}

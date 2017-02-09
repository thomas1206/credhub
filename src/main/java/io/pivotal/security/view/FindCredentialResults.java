package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedSecretData;

import static com.google.common.collect.Lists.newArrayList;

import java.util.List;

public class FindCredentialResults {
  private List<Credential> credentials;

  @SuppressWarnings("rawtypes")
  FindCredentialResults(List<Credential> credentials) {
    this.credentials = credentials;
  }

  public static FindCredentialResults fromEntity(List<NamedSecretData> secrets) {
    List<Credential> credentials = newArrayList();
    for(NamedSecretData s: secrets) {
      credentials.add(new Credential(s.getName(), s.getVersionCreatedAt()));
    }
    return new FindCredentialResults(credentials);
  }

  @JsonProperty
  public List<Credential> getCredentials() {
    return credentials;
  }

}

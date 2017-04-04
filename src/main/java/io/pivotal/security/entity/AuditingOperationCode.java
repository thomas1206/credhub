package io.pivotal.security.entity;

public enum AuditingOperationCode {
  ACL_ACCESS("acl_access"),
  CREDENTIAL_ACCESS("credential_access"),
  CREDENTIAL_FIND("credential_find"),
  CREDENTIAL_DELETE("credential_delete"),
  CREDENTIAL_UPDATE("credential_update"),
  CA_ACCESS("ca_access"),
  CA_UPDATE("ca_update"),
  UNKNOWN_OPERATION("unknown_operation");

  private String operation;

  AuditingOperationCode(String operation) {
    this.operation = operation;
  }

  public String toString() {
    return operation;
  }
}

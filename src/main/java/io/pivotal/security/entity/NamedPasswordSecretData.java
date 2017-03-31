package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;

@Entity
@DiscriminatorValue(NamedPasswordSecretData.SECRET_TYPE)
@SecondaryTable(
    name = NamedPasswordSecretData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class NamedPasswordSecretData extends NamedSecretData<NamedPasswordSecretData> {

  public static final String SECRET_TYPE = "password";
  static final String TABLE_NAME = "PasswordSecret";
  @Column(table = NamedPasswordSecretData.TABLE_NAME, length = 255 + NONCE_SIZE)
  private byte[] encryptedGenerationParameters = {};
  @Column(table = NamedPasswordSecretData.TABLE_NAME, length = NONCE_SIZE)
  private byte[] parametersNonce = {};

  @SuppressWarnings("unused")
  public NamedPasswordSecretData() {
  }

  public NamedPasswordSecretData(String name) {
    super(name);
  }

  public byte[] getEncryptedGenerationParameters() {
    return DEFENSIVE_COPIER.copyByteArray(encryptedGenerationParameters);
  }

  public NamedPasswordSecretData setEncryptedGenerationParameters(
      byte[] encryptedGenerationParameters) {
    this.encryptedGenerationParameters = DEFENSIVE_COPIER.copyByteArray(encryptedGenerationParameters);

    return this;
  }

  public byte[] getParametersNonce() {
    return DEFENSIVE_COPIER.copyByteArray(parametersNonce);
  }

  public NamedPasswordSecretData setParametersNonce(byte[] parametersNonce) {
    this.parametersNonce = DEFENSIVE_COPIER.copyByteArray(parametersNonce);
    return this;
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }

  @Override
  public void copyIntoImpl(NamedPasswordSecretData copy) {
    copy.setEncryptedGenerationParameters(encryptedGenerationParameters);
    copy.setParametersNonce(parametersNonce);
  }

  @Override
  public SecretKind getKind() {
    return SecretKind.PASSWORD;
  }
}

package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.generator.CredHubCharacterData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.Encryption;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.PasswordData;

import java.util.ArrayList;
import java.util.List;

public class NamedPasswordSecret extends NamedSecret<NamedPasswordSecret> {

  private NamedPasswordSecretData delegate;
  private String password;

  public NamedPasswordSecret(NamedPasswordSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedPasswordSecret(String name) {
    this(new NamedPasswordSecretData(name));
  }

  public NamedPasswordSecret() {
    this(new NamedPasswordSecretData());
  }

  public static NamedPasswordSecret createNewVersion(
      NamedPasswordSecret existing,
      String name,
      String password,
      Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries) {
    NamedPasswordSecret secret;

    if (existing == null) {
      secret = new NamedPasswordSecret(name);
    } else {
      secret = new NamedPasswordSecret();
      secret.copyNameReferenceFrom(existing);
    }

    if (accessControlEntries == null) {
      accessControlEntries = new ArrayList<>();
    }

    secret.setAccessControlList(accessControlEntries);

    secret.setEncryptor(encryptor);
    secret.setPassword(password);
    return secret;
  }

  public String getPassword() {
    if (password == null) {
      password = encryptor.decrypt(
          delegate.getEncryptionKeyUuid(),
          delegate.getEncryptedValue(),
          delegate.getNonce()
      );
    }
    return password;
  }

  public NamedPasswordSecret setPassword(String password) {
    if (password == null) {
      throw new IllegalArgumentException("password cannot be null");
    }

    try {
      Encryption encryptedPassword = encryptor.encrypt(password);
      delegate.setEncryptedValue(encryptedPassword.encryptedValue);
      delegate.setNonce(encryptedPassword.nonce);

      delegate.setEncryptionKeyUuid(encryptedPassword.canaryUuid);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return this;
  }

  public StringGenerationParameters getGenerationParameters() {
    final String password = getPassword();
    final PasswordData passwordData = new PasswordData(password);

    final StringGenerationParameters stringGenerationParameters = new StringGenerationParameters();

    final CharacterRule specialRule = new CharacterRule(CredHubCharacterData.Special);
    final CharacterRule digitRule = new CharacterRule(EnglishCharacterData.Digit);
    final CharacterRule upperCaseRule = new CharacterRule(EnglishCharacterData.UpperCase);
    final CharacterRule lowerCaseRule = new CharacterRule(EnglishCharacterData.LowerCase);

    stringGenerationParameters.setLength(password.length());
    stringGenerationParameters.setIncludeSpecial(specialRule.validate(passwordData).isValid());
    stringGenerationParameters.setExcludeNumber(!digitRule.validate(passwordData).isValid());
    stringGenerationParameters.setExcludeUpper(!upperCaseRule.validate(passwordData).isValid());
    stringGenerationParameters.setExcludeLower(!lowerCaseRule.validate(passwordData).isValid());

    return stringGenerationParameters;
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  public void rotate() {
    String decryptedPassword = this.getPassword();
    this.setPassword(decryptedPassword);
  }
}

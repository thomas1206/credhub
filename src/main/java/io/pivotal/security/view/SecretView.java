package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.entity.NamedStringSecretData;

import java.time.Instant;
import java.util.UUID;

public class SecretView extends BaseView {

  private final UUID uuid;
  private final String name;
  private final String type;
  private final Object value;

  public SecretView(Instant versionCreatedAt, String name) {
    this(versionCreatedAt, null, name, "", "");
  }

  SecretView(Instant versionCreatedAt, UUID uuid, String name, String type, Object value) {
    super(versionCreatedAt);
    this.uuid = uuid;
    this.name = name;
    this.type = type;
    this.value = value;
  }

  @JsonProperty
  public String getType() {
    return type;
  }

  @JsonProperty("id")
  public String getUuid() {
    return uuid == null ? "" : uuid.toString();
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("value")
  public Object getValue() {
    return value;
  }

  public static SecretView fromEntity(NamedSecretData namedSecret) {
    SecretView result;
    if (NamedStringSecretData.class.isInstance(namedSecret)) {
      result =  new StringView((NamedStringSecretData) namedSecret);
    } else if (NamedCertificateSecretData.class.isInstance(namedSecret)) {
      result = new CertificateView((NamedCertificateSecretData) namedSecret);
    } else if (NamedSshSecretData.class.isInstance(namedSecret)) {
      result = new SshView((NamedSshSecretData) namedSecret);
    } else if (NamedRsaSecretData.class.isInstance(namedSecret)) {
      result = new RsaView((NamedRsaSecretData) namedSecret);
    } else {
      throw new IllegalArgumentException();
    }
    return result;
  }
}

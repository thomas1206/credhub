package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateGenerationParameters {
  private String caName;

  private String organization;
  private String state;
  private String country;
  private String commonName;
  private String organizationUnit;
  private String locality;

  private String[] alternativeNames;
  private String[] keyUsage;
  private String[] extendedKeyUsage;
  private int keyLength = 2048; // todo: how to handle defaults
  private int durationDays = 365; // todo: how to handle defaults
  private boolean selfSigned;
  private boolean isCA;

  @JsonProperty("ca")
  public String getCaName() {
    return caName;
  }

  @JsonProperty("common_name")
  public String getCommonName() {
    return commonName;
  }

  @JsonProperty("organization")
  public String getOrganization() {
    return organization;
  }

  @JsonProperty("state")
  public String getState() {
    return state;
  }

  @JsonProperty("country")
  public String getCountry() {
    return country;
  }

  @JsonProperty("organization_unit")
  public String getOrganizationUnit() {
    return organizationUnit;
  }

  @JsonProperty("locality")
  public String getLocality() {
    return locality;
  }

  @JsonProperty("key_length")
  public int getKeyLength() {
    return keyLength;
  }

  @JsonProperty("duration")
  public int getDurationDays() {
    return durationDays;
  }

  @JsonProperty("self_sign")
  public boolean isSelfSigned() {
    return selfSigned;
  }

  @JsonProperty("is_ca")
  public boolean isCA() {
    return isCA;
  }

  @JsonProperty("alternative_names")
  public String[] getAlternativeNames() {
    return alternativeNames;
  }

  @JsonProperty("key_usage")
  public String[] getKeyUsage() {
    return keyUsage;
  }

  @JsonProperty("extended_key_usage")
  public String[] getExtendedKeyUsage() {
    return extendedKeyUsage;
  }
}

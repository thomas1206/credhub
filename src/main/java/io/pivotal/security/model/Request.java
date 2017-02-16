package io.pivotal.security.model;

public abstract class Request {
  private String name;
  private String type;
  private boolean regenerate;
  private boolean overwrite;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public boolean isRegenerate() {
    return regenerate;
  }

  public void setRegenerate(boolean regenerate) {
    this.regenerate = regenerate;
  }

  public boolean isOverwrite() {
    return overwrite;
  }

  public void setOverwrite(boolean overwrite) {
    this.overwrite = overwrite;
  }
}

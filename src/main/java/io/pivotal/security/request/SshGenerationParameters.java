package io.pivotal.security.request;

import org.springframework.stereotype.Component;

@Component
public class SshGenerationParameters extends RsaSshGenerationParameters {

  private String sshComment = "";

  public String getSshComment() {
    return sshComment;
  }

  public void setSshComment(String sshComment) {
    this.sshComment = sshComment;
  }
}

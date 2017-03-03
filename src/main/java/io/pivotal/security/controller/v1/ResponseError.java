package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect
public class ResponseError {
  public String error;

  public ResponseError(ResponseErrorType type) {
    this.error = type.getError();
  }

  public String getError() {
    return error;
  }
}

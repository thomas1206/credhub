package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.InvalidJsonException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;


@ControllerAdvice
public class ControllerErrorHandler extends ResponseEntityExceptionHandler {

  @ExceptionHandler({InvalidJsonException.class})
  @ResponseBody
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  ResponseError handleControllerException() {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }

}

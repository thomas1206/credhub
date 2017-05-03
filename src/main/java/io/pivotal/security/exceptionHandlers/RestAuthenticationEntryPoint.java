package io.pivotal.security.exceptionHandlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.view.ResponseError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON;

@Component
@ControllerAdvice
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

  private final ObjectMapper objectMapper;

  @Autowired
  public RestAuthenticationEntryPoint(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException ) throws IOException, ServletException {
    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
  }

  @ExceptionHandler(value = { AccessDeniedException.class })
  public void commence(HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex) throws IOException {

    ResponseError responseError = new ResponseError("The request could not be completed because the credential does not exist or you do not have sufficient authorization.");

    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(APPLICATION_JSON.getType());
    response.getWriter().write(objectMapper.writeValueAsString(responseError));
  }
}
package io.pivotal.security.exceptionHandlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.view.ResponseError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON;

@Component
public class ActorAccessDeniedHandler implements AccessDeniedHandler {

  private ObjectMapper objectMapper;

  @Autowired
  public ActorAccessDeniedHandler(ObjectMapper objectMapper){

    this.objectMapper = objectMapper;
  }

  @Override
  public void handle
      (HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex)
      throws IOException, ServletException {

    ResponseError responseError = new ResponseError("The request could not be completed because the credential does not exist or you do not have sufficient authorization.");

    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(APPLICATION_JSON.getType());
    response.getWriter().write(objectMapper.writeValueAsString(responseError));
  }
}
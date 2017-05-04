package io.pivotal.security.controller.v1.credential;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.exceptions.InvalidQueryParameterException;
import io.pivotal.security.handler.CredentialHandler;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.request.CredentialRegenerateRequest;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.service.RegenerateService;
import io.pivotal.security.service.SetService;
import io.pivotal.security.view.CredentialView;
import io.pivotal.security.view.DataResponse;
import io.pivotal.security.view.FindCredentialResult;
import io.pivotal.security.view.FindCredentialResults;
import io.pivotal.security.view.FindPathResults;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.util.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.orm.jpa.JpaSystemException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;
import java.util.function.Function;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_FIND;

@RestController
@RequestMapping(
    path = CredentialsController.API_V1_DATA,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class CredentialsController {

  public static final String API_V1_DATA = "/api/v1/data";

  private static final Logger LOGGER = LogManager.getLogger(CredentialsController.class);
  private final CredentialDataService credentialDataService;
  private final EventAuditLogService eventAuditLogService;
  private final ObjectMapper objectMapper;
  private final GenerateService generateService;
  private final SetService setService;
  private final RegenerateService regenerateService;
  private final CredentialHandler credentialHandler;

  @Autowired
  public CredentialsController(CredentialDataService credentialDataService,
                               EventAuditLogService eventAuditLogService,
                               ObjectMapper objectMapper,
                               GenerateService generateService,
                               SetService setService,
                               RegenerateService regenerateService,
                               CredentialHandler credentialHandler
  ) {
    this.credentialDataService = credentialDataService;
    this.eventAuditLogService = eventAuditLogService;
    this.objectMapper = objectMapper;
    this.generateService = generateService;
    this.setService = setService;
    this.regenerateService = regenerateService;
    this.credentialHandler = credentialHandler;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView generate(InputStream inputStream,
                                 RequestUuid requestUuid,
                                 UserContext userContext,
                                 AccessControlEntry currentUserAccessControlEntry) throws IOException {
    InputStream requestInputStream = new ByteArrayInputStream(ByteStreams.toByteArray(inputStream));
    try {
      return auditedHandlePostRequest(requestInputStream, requestUuid, userContext,
          currentUserAccessControlEntry);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      requestInputStream.reset();
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing credential, possibly caused by race condition, retrying...");
      return auditedHandlePostRequest(requestInputStream, requestUuid, userContext,
          currentUserAccessControlEntry);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("@authorization.hasAccess(#requestBody, #userContext)")
  public CredentialView set(@RequestBody BaseCredentialSetRequest requestBody,
                            RequestUuid requestUuid,
                            UserContext userContext,
                            AccessControlEntry currentUserAccessControlEntry) {
    requestBody.validate();

    try {
      return auditedHandlePutRequest(requestBody, requestUuid, userContext,
          currentUserAccessControlEntry);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing credential, possibly caused by race condition, retrying...");
      return auditedHandlePutRequest(requestBody, requestUuid, userContext,
          currentUserAccessControlEntry);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void delete(
      @RequestParam(value = "name") String credentialName,
      RequestUuid requestUuid,
      UserContext userContext
  ) {
    if (StringUtils.isEmpty(credentialName)) {
      throw new InvalidQueryParameterException("error.missing_query_parameter", "name");
    }

    eventAuditLogService.auditEvent(requestUuid, userContext, (eventAuditRecordParameters) -> {
      eventAuditRecordParameters.setCredentialName(credentialName);
      eventAuditRecordParameters.setAuditingOperationCode(AuditingOperationCode.CREDENTIAL_DELETE);

      credentialHandler.deleteCredential(credentialName);

      return true;
    });
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView getCredentialById(
      @PathVariable String id,
      RequestUuid requestUuid,
      UserContext userContext) {
    return eventAuditLogService.auditEvent(requestUuid, userContext, eventAuditRecordParameters -> (
        credentialHandler.getCredentialVersion(userContext, eventAuditRecordParameters, id)
    ));
  }

  @GetMapping(path = "")
  @ResponseStatus(HttpStatus.OK)
  public DataResponse getCredential(
      @RequestParam(value = "name") String credentialName,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current,
      RequestUuid requestUuid,
      UserContext userContext) {
    if (StringUtils.isEmpty(credentialName)) {
      throw new InvalidQueryParameterException("error.missing_query_parameter", "name");
    }

    return eventAuditLogService.auditEvent(requestUuid, userContext, eventAuditRecordParameters -> {
      if (current) {
        return credentialHandler.getMostRecentCredentialVersion(userContext, eventAuditRecordParameters, credentialName);
      } else {
        return credentialHandler.getAllCredentialVersions(userContext, eventAuditRecordParameters, credentialName);
      }
    });
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByPath(
      @RequestParam("path") String path,
      RequestUuid requestUuid,
      UserContext userContext
  ) {
    return findWithAuditing(path, credentialDataService::findStartingWithPath, requestUuid, userContext);
  }

  @RequestMapping(path = "", params = "paths=true", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindPathResults findPaths(RequestUuid requestUuid, UserContext userContext) {
    return eventAuditLogService.auditEvent(requestUuid, userContext, eventAuditRecordParameters -> {
      eventAuditRecordParameters.setAuditingOperationCode(CREDENTIAL_FIND);
      List<String> paths = credentialDataService.findAllPaths();
      return FindPathResults.fromEntity(paths);
    });
  }

  @RequestMapping(path = "", params = "name-like", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByNameLike(
      @RequestParam("name-like") String nameLike,
      RequestUuid requestUuid,
      UserContext userContext
  ) {
    return findWithAuditing(nameLike, credentialDataService::findContainingName, requestUuid,
        userContext);
  }

  private CredentialView auditedHandlePostRequest(
      InputStream inputStream,
      RequestUuid requestUuid,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    return eventAuditLogService
        .auditEvent(requestUuid, userContext, (auditRecordParameters -> {
          return deserializeAndHandlePostRequest(
              inputStream,
              userContext,
              auditRecordParameters,
              currentUserAccessControlEntry);
        }));
  }

  private CredentialView deserializeAndHandlePostRequest(
      InputStream inputStream,
      UserContext userContext,
      EventAuditRecordParameters eventAuditRecordParameters,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    try {
      String requestString = IOUtils.toString(new InputStreamReader(inputStream));
      boolean isRegenerateRequest = readRegenerateFlagFrom(requestString);

      if (isRegenerateRequest) {
        // If it's a regenerate request deserialization is simple; the generation case requires
        // polymorphic deserialization See BaseCredentialGenerateRequest to see how that's done. It
        // would be nice if Jackson could pick a subclass based on an arbitrary function, since
        // we want to consider both type and .regenerate. We could do custom deserialization but
        // then we'd have to do the entire job by hand.
        return handleRegenerateRequest(userContext, eventAuditRecordParameters, requestString,
            currentUserAccessControlEntry);
      } else {
        return handleGenerateRequest(userContext, eventAuditRecordParameters, requestString,
            currentUserAccessControlEntry);
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private CredentialView handleGenerateRequest(
      UserContext userContext,
      EventAuditRecordParameters eventAuditRecordParameters,
      String requestString,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    BaseCredentialGenerateRequest requestBody = objectMapper
        .readValue(requestString, BaseCredentialGenerateRequest.class);
    requestBody.validate();

    return generateService
        .performGenerate(userContext, eventAuditRecordParameters, requestBody, currentUserAccessControlEntry);
  }

  private CredentialView handleRegenerateRequest(
      UserContext userContext,
      EventAuditRecordParameters eventAuditRecordParameters,
      String requestString,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    CredentialRegenerateRequest requestBody = objectMapper
        .readValue(requestString, CredentialRegenerateRequest.class);

    return regenerateService
        .performRegenerate(userContext, eventAuditRecordParameters, requestBody, currentUserAccessControlEntry);
  }

  private CredentialView auditedHandlePutRequest(
      @RequestBody BaseCredentialSetRequest requestBody,
      RequestUuid requestUuid,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    return eventAuditLogService.auditEvent(requestUuid, userContext, eventAuditRecordParameters ->
        handlePutRequest(requestBody, userContext, eventAuditRecordParameters, currentUserAccessControlEntry));
  }

  private CredentialView handlePutRequest(
      @RequestBody BaseCredentialSetRequest requestBody,
      UserContext userContext,
      EventAuditRecordParameters eventAuditRecordParameters,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    return setService
        .performSet(userContext, eventAuditRecordParameters, requestBody, currentUserAccessControlEntry);
  }

  private boolean readRegenerateFlagFrom(String requestString) {
    boolean isRegenerateRequest;
    try {
      isRegenerateRequest = JsonPath.read(requestString, "$.regenerate");
    } catch (PathNotFoundException e) {
      // could have just returned null, that would have been pretty useful
      isRegenerateRequest = false;
    }
    return isRegenerateRequest;
  }

  private FindCredentialResults findWithAuditing(String nameSubstring,
      Function<String, List<FindCredentialResult>> finder,
      RequestUuid requestUuid,
      UserContext userContext) {
    return eventAuditLogService
        .auditEvent(requestUuid, userContext, eventAuditRecordParameters -> {
          eventAuditRecordParameters.setAuditingOperationCode(CREDENTIAL_FIND);
          return new FindCredentialResults(finder.apply(nameSubstring));
        });
  }
}

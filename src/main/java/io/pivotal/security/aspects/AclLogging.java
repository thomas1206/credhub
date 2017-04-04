package io.pivotal.security.aspects;

import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.SecurityEventsLogService;
import io.pivotal.security.util.CurrentTimeProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.transaction.PlatformTransactionManager;

@Aspect
public class AclLogging {
  private final Logger logger = LogManager.getLogger();
  private SecurityEventsLogService securityEventsLogService;
  private PlatformTransactionManager transactionManager;
  private CurrentTimeProvider currentTimeProvider;
  private ResourceServerTokenServices tokenServices;
  private OperationAuditRecordDataService operationAuditRecordDataService;
  private MessageSourceAccessor messageSourceAccessor;
  private AuditLogService auditLogService;

  public void setAclLogging(SecurityEventsLogService securityEventsLogService,
                            PlatformTransactionManager transactionManager,
                            CurrentTimeProvider currentTimeProvider,
                            ResourceServerTokenServices tokenServices,
                            OperationAuditRecordDataService operationAuditRecordDataService,
                            MessageSource messageSource,
                            AuditLogService auditLogService) {
    this.securityEventsLogService = securityEventsLogService;
    this.transactionManager = transactionManager;
    this.currentTimeProvider = currentTimeProvider;
    this.tokenServices = tokenServices;
    this.operationAuditRecordDataService = operationAuditRecordDataService;
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
    this.auditLogService = auditLogService;
  }

  @Around("execution(public * io.pivotal.security.controller.v1.permissions.AccessControlListController.getAccessControlList(..)) && args(credentialName)")
  public void logBefore(ProceedingJoinPoint joinPoint, String credentialName) throws Throwable {
    auditLogService.performWithAuditing(auditRecordBuilder -> {
      auditRecordBuilder.setOperationCode(AuditingOperationCode.ACL_ACCESS);
      return (ResponseEntity) joinPoint.proceed();
    });
  }
}

//    AuditRecordBuilder auditRecordBuilder = new AuditRecordBuilder();
//    auditRecordBuilder.setOperationCode(AuditingOperationCode.ACL_ACCESS);
//    OperationAuditRecord auditRecord = auditRecordBuilder.build(currentTimeProvider.getInstant(), tokenServices);
//    securityEventsLogService.log(auditRecord);
//
//
//    ResponseEntity<?> responseEntity = new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
//    boolean responseSucceeded = false;
//
//    TransactionStatus transaction =
//      transactionManager.getTransaction(new DefaultTransactionDefinition());
//    try {
//      responseEntity = (ResponseEntity<?>) joinPoint.proceed();
//      responseSucceeded = responseEntity.getStatusCode().is2xxSuccessful();
//    } finally {
//      try {
//        if (!responseSucceeded) {
//          transactionManager.rollback(transaction);
//          transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
//        }
//        auditRecordBuilder.setIsSuccess(responseSucceeded);
//
//        OperationAuditRecord auditRecord = auditRecordBuilder
//          .setRequestStatus(responseEntity.getStatusCode())
//          .build(currentTimeProvider.getInstant(), tokenServices);
//
//        operationAuditRecordDataService.save(auditRecord);
//
//        transactionManager.commit(transaction);
//        securityEventsLogService.log(auditRecord);
//      } catch (Exception e) {
//        if (!transaction.isCompleted()) {
//          transactionManager.rollback(transaction);
//        }
//        ResponseError error = new ResponseError(
//          messageSourceAccessor.getMessage("error.audit_save_failure"));
//        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
//      }
//    }
//
//    return responseEntity;

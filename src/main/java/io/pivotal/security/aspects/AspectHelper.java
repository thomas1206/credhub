package io.pivotal.security.aspects;

import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.ExceptionThrowingFunction;
import org.aspectj.lang.ProceedingJoinPoint;
import org.springframework.http.ResponseEntity;

/**
 * Created by pivotal on 4/5/17.
 */
public class AspectHelper {
  public static ExceptionThrowingFunction<AuditRecordBuilder, ResponseEntity<?>, Throwable> setResponse(ProceedingJoinPoint joinPoint) {
    return (auditRecordBuilder) -> {
      auditRecordBuilder.setOperationCode(AuditingOperationCode.ACL_ACCESS);
      return (ResponseEntity) joinPoint.proceed();
    };
  }
}

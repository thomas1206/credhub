package io.pivotal.security.aspects;

import io.pivotal.security.service.SecurityEventsLogService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;

@Aspect
public class TLSLogger {
  private final Logger logger = LogManager.getLogger();
  private SecurityEventsLogService securityEventsLogService;

  public void setSecurityEventsLogService(SecurityEventsLogService securityEventsLogService) {
    this.securityEventsLogService = securityEventsLogService;
  }

//  @Before("execution(public * io.pivotal.security.controller.v1.secret.SecretsController.*(..))")
  @Before("execution(* java.security.cert.X509Certificate.checkValidity(Date))")
  public void logBefore(JoinPoint joinPoint) {
    logger.debug("*****************************");
    logger.debug("Ashwin and Kelly in the hizzouse");
    logger.debug("*****************************");
  }

  @Before("execution(* java.security.cert.X509Certificate.*(..))")
  public void logBeforeANYTRHING(JoinPoint joinPoint) {
    logger.debug("*****************************");
    logger.debug("Ashwin and Kelly in the hizzouse");
    logger.debug("*****************************");
  }

  @Before("execution(* sun.security.x509.X509CertImpl.*(..))")
  public void logBeforeSun(JoinPoint joinPoint) {
    logger.debug("*****************************");
    logger.debug("Ashwin and Kelly in the hizzouse");
    logger.debug("*****************************");
  }
}

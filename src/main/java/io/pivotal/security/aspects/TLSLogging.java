//package io.pivotal.security.aspects;
//
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;
//import org.aspectj.lang.JoinPoint;
//import org.aspectj.lang.annotation.Aspect;
//import org.aspectj.lang.annotation.Before;
//
//@Aspect
//public class TLSLogging {
//  private final Logger logger = LogManager.getLogger();
//
//  @Before("execution(public * io.pivotal.security.controller.v1.secret.SecretsController.*(..))")
//  public void logBefore(JoinPoint joinPoint) {
//    logger.debug("*****************************");
//    logger.debug("Ashwin and Kelly in the hizzouse");
//    logger.debug("*****************************");
//  }
//}

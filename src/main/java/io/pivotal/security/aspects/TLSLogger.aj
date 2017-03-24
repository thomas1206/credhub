package io.pivotal.security.aspects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public aspect TLSLogger {
  private final Logger logger = LogManager.getLogger();

  pointcut generateMethod(): call(* io.pivotal.security.controller.v1.secret.SecretsController.*(..));

  before(): generateMethod() {
    logger.debug("********************************************");
    logger.debug("fizz buzz");
    logger.debug("********************************************");
  }
}

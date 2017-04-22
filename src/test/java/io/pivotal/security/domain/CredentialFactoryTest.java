//package io.pivotal.security.domain;
//
//import io.pivotal.security.credential.Certificate;
//import io.pivotal.security.credential.StringCredential;
//import org.junit.Test;
//import org.junit.runner.RunWith;
//import org.junit.runners.JUnit4;
//
//import java.util.ArrayList;
//
//import static com.google.common.collect.Lists.newArrayList;
//import static io.pivotal.security.domain.CredentialFactory.createNewVersion;
//import static org.hamcrest.CoreMatchers.equalTo;
//import static org.hamcrest.MatcherAssert.assertThat;
//
//@RunWith(JUnit4.class)
//public class CredentialFactoryTest {
//  @Test
//  public void createNewVersion_givenAPasswordView_andNoExistingCredential_returnsPassword() {
//    PasswordCredential newCredential = (PasswordCredential) createNewVersion(
//        null,
//        "/newName",
//        new StringCredential("test-password"),
//        newArrayList());
//
//    assertThat(newCredential.getName(), equalTo("/newName"));
//    assertThat(newCredential.getPassword(), equalTo("test-password"));
//  }
//
//  @Test
//  public void createNewVersion_givenACertificateView_andNoExistingCredential_returnsCertificate() {
//    Certificate certificateValue = new Certificate(
//        "ca", "certificate", "new private key", null);
//    CertificateCredential newCredential = (CertificateCredential) createNewVersion(null, "/newName", certificateValue, new ArrayList<>());
//
//    assertThat(newCredential.getName(), equalTo("/newName"));
//    assertThat(newCredential.getPrivateKey(), equalTo("new private key"));
//    assertThat(newCredential.getCa(), equalTo("ca"));
//    assertThat(newCredential.getCertificate(), equalTo("certificate"));
//    assertThat(newCredential.getCaName(), equalTo(null));
//  }
//
//  @Test
//  public void createNewVersion_givenACertificateView_andAnExistingCertificate_returnsCertificate() {
//    Certificate certificateValue = new Certificate(
//        "ca", "certificate", "new private key", null);
//    CertificateCredential certificateCredential = new CertificateCredential("/test/name");
//    certificateCredential.setCertificate("my-cert");
//    certificateCredential.setPrivateKey("my-priv");
//
//    CertificateCredential newCredential = (CertificateCredential) createNewVersion(
//        certificateCredential,
//        "anything I AM IGNORED",
//        certificateValue,
//        new ArrayList<>()
//    );
//
//    assertThat(newCredential.getName(), equalTo("/test/name"));
//    assertThat(newCredential.getPrivateKey(), equalTo("new private key"));
//    assertThat(newCredential.getCa(), equalTo("ca"));
//    assertThat(newCredential.getCertificate(), equalTo("certificate"));
//    assertThat(newCredential.getCaName(), equalTo(null));
//  }
//}

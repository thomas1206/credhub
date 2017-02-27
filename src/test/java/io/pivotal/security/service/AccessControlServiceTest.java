package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessEntryResponse;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AccessControlServiceTest {

    @Autowired
    private AccessControlService subject;

    @Autowired
    private SecretNameRepository secretNameRepository;

    @Autowired
    private AccessEntryRepository accessEntryRepository;

    private AccessEntryRequest request;

    private SecretName secretName;

    {
        wireAndUnwire(this);

        describe("setAccessControlEntry", () -> {
            describe("when given an existing ACE for a resource", () -> {
                beforeEach(() -> {
                    SecretName secretName = secretNameRepository.saveAndFlush(new SecretName("lightsaber"));

                    accessEntryRepository.saveAndFlush(new AccessEntryData(secretName,
                            "Luke",
                            false,
                            true));

                    accessEntryRepository.saveAndFlush(new AccessEntryData(secretName,
                            "Leia",
                            true,
                            false));

                    List<AccessControlEntry> newAces = Collections.singletonList(
                            new AccessControlEntry("Luke", Collections.singletonList("read")));


                    request = new AccessEntryRequest("/lightsaber", newAces);
                });

                it("returns the acl for the given resource", () -> {
                    AccessEntryResponse response = subject.setAccessControlEntry(request);

                    assertThat(response.getResource(), equalTo("/lightsaber"));
                    assertThat(response.getAcls().get(0).getActor(), equalTo("Luke"));
                    assertThat(response.getAcls().get(0).getOperations().size(), equalTo(2));
                    assertThat(response.getAcls().get(0).getOperations(), hasItem("read"));
                    assertThat(response.getAcls().get(0).getOperations(), hasItem("write"));
                    assertThat(response.getAcls().get(1).getActor(), equalTo("Leia"));
                    assertThat(response.getAcls().get(1).getOperations().size(), equalTo(1));
                    assertThat(response.getAcls().get(1).getOperations(), hasItem("read"));

                    AccessEntryData data = accessEntryRepository.findAll().stream()
                            .filter((entry) -> entry.getActor().equals("Luke")).findFirst().get();

                    assertThat(data.getRead(), equalTo(true));
                    assertThat(data.getWrite(), equalTo(true));
                });
            });

            describe("when given a new ACE for a resource", () -> {
                beforeEach(() -> {
                    secretName = secretNameRepository.saveAndFlush(new SecretName("lightsaber"));

                    List<AccessControlEntry> newAces = Collections.singletonList(
                            new AccessControlEntry("Luke", Collections.singletonList("read")));


                    request = new AccessEntryRequest("/lightsaber", newAces);
                });

                it("returns the acl for the given resource", () -> {
                    AccessEntryResponse response = subject.setAccessControlEntry(request);

                    assertThat(response.getResource(), equalTo("/lightsaber"));
                    assertThat(response.getAcls().get(0).getActor(), equalTo("Luke"));
                    assertThat(response.getAcls().get(0).getOperations().size(), equalTo(2));
                    assertThat(response.getAcls().get(0).getOperations(), hasItem("read"));
                    assertThat(response.getAcls().get(0).getOperations(), hasItem("write"));

                    AccessEntryData data = accessEntryRepository.findAll().stream()
                            .filter((entry) -> entry.getActor().equals("Luke")).findFirst().get();

                    assertThat(data.getRead(), equalTo(true));
                    assertThat(data.getWrite(), equalTo(false));
                    assertThat(data.getResource(), equalTo(secretName));
                });
            });
        });
    }
}
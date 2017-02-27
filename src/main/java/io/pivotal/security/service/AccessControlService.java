package io.pivotal.security.service;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.view.AccessEntryResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class AccessControlService {

    private AccessEntryRepository accessEntryRepository;
    private SecretNameRepository secretNameRepository;

    @Autowired
    public AccessControlService(AccessEntryRepository accessEntryRepository,
                                SecretNameRepository secretNameRepository) {
        this.accessEntryRepository = accessEntryRepository;
        this.secretNameRepository = secretNameRepository;
    }

    public AccessEntryResponse setAccessControlEntry(AccessEntryRequest request) {

        SecretName secretName = secretNameRepository.findOneByNameIgnoreCase(request.getResource());
        List<AccessEntryData> data = accessEntryRepository.findAllByResourceUuid(secretName.getUuid());

        for (AccessControlEntry ace : request.getAces()) {
            Optional<AccessEntryData> datum = data.stream()
                    .filter((accessEntryData -> accessEntryData.getActor().equals(ace.getActor())))
                    .findFirst();

            if (datum.isPresent()) {
                for (String operation : ace.getOperations()) {
                    switch (operation) {
                        case "read":
                            datum.get().setRead(true);
                            break;
                        case "write":
                            datum.get().setWrite(true);
                            break;
                    }
                }
            } else {

                List<String> operations = request.getAces().stream().map(x -> {
                    return x.getOperations();
                });

                accessEntryRepository.saveAndFlush(new AccessEntryData(secretName,
                        ace.getActor(),
                        ,
                        true));
            }

            accessEntryRepository.saveAndFlush(datum.get());

        }

        List<AccessControlEntry> responseAces = data.stream().map(this::transformData)
                .collect(Collectors.toList());

        return new AccessEntryResponse(request.getResource(), responseAces);
    }

    private AccessControlEntry transformData(AccessEntryData data) {
        AccessControlEntry entry = new AccessControlEntry();
        List<String> operations = new ArrayList<>();
        if (data.getRead()) {
            operations.add("read");
        }
        if (data.getWrite()) {
            operations.add("write");
        }
        entry.setOperations(operations);
        entry.setActor(data.getActor());
        return entry;
    }
}

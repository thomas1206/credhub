package io.pivotal.security.repository;


import io.pivotal.security.entity.AccessEntryData;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccessEntryRepository extends JpaRepository<AccessEntryData, UUID> {

  List<AccessEntryData> findAllByCredentialNameUuid(UUID name);

  AccessEntryData findByCredentialNameUuidAndActor(UUID uuid, String actor);

//  @Transactional
  void delete(AccessEntryData data);
}

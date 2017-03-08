package io.pivotal.security.view;

import io.pivotal.security.request.AccessControlEntry;
import org.codehaus.jackson.annotate.JsonAutoDetect;

import java.util.List;

@JsonAutoDetect
public class AccessControlListResponse {

    private String credentialName;
    private List<AccessControlEntry> accessControlList;

    @SuppressWarnings("unused")
    public AccessControlListResponse() {
    }

    public AccessControlListResponse(String credentialName, List<AccessControlEntry> accessControlList) {
        this.credentialName = credentialName;
        this.accessControlList = accessControlList;
    }

    public String getCredentialName() {
        return credentialName;
    }

    @SuppressWarnings("unused")
    public void setCredentialName(String credentialName) {
        this.credentialName = credentialName;
    }

    public List<AccessControlEntry> getAccessControlList() {
        return accessControlList;
    }

    @SuppressWarnings("unused")
    public void setAccessControlList(List<AccessControlEntry> accessControlList) {
        this.accessControlList = accessControlList;
    }
}

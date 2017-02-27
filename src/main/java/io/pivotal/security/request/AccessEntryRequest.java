package io.pivotal.security.request;

import org.codehaus.jackson.annotate.JsonAutoDetect;

import javax.validation.constraints.NotNull;
import java.util.List;

@JsonAutoDetect
public class AccessEntryRequest {

    @NotNull
    private String resource;

    public AccessEntryRequest(String resource, List<AccessControlEntry> aces) {
        this.resource = resource;
        this.aces = aces;
    }

    @NotNull
    private List<AccessControlEntry> aces;

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public List<AccessControlEntry> getAces() {
        return aces;
    }

    public void setAces(List<AccessControlEntry> aces) {
        this.aces = aces;
    }
}

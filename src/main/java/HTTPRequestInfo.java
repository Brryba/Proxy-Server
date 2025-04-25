import lombok.Data;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

@Data
public class HTTPRequestInfo {
    private String request;
    private String method;
    private String protocol;
    private String protocolVersion;
    private String absoluteUri;
    private String pathUri;
    private String host;
    private int port;

    public void setRequestData(byte[] requestData, int requestLength) throws IllegalArgumentException {
        String request = new String(requestData, 0, requestLength);
        this.request = request;
        String[] requestParts = request.split("\n");

        String[] firstLineParts = requestParts[0].split(" ");
        this.method = firstLineParts[0];

        String URI = firstLineParts[1].trim();
        this.absoluteUri = URI;
        URI = URI.replace("https://", "").replace("http://", "");
        int index = URI.indexOf("/");
        this.pathUri = index > -1 ? URI.substring(index) : "/";

        this.protocol = firstLineParts[2].split("/")[0];
        this.protocolVersion = firstLineParts[2].split("/")[1];

        String hostParameter = Arrays.stream(requestParts)
                .filter(str -> str.startsWith("Host:"))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Host parameter missing"));

        hostParameter = hostParameter.substring(hostParameter.indexOf(":") + 2).trim();
        if (hostParameter.contains(":")) {
            this.host = hostParameter.substring(0, hostParameter.indexOf(":"));
            this.port = Integer.parseInt(hostParameter.substring(hostParameter.indexOf(":") + 1).trim());
        }

        else {
            this.host = hostParameter;
            this.port = protocol.equalsIgnoreCase("HTTP") ? 80 : 443;
        }
    }

    public String getRequestWithPathUri() {
        return this.request.replace(this.absoluteUri, this.pathUri);
    }
}

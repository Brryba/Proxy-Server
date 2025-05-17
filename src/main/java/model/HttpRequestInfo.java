package model;

import lombok.Getter;

import java.util.Arrays;

@Getter
public class HttpRequestInfo {
    private String request;
    private String method;
    private String protocol;
    private String absoluteUri;
    private String pathUri;
    private String host;
    private int port;

    public void setRequestData(byte[] requestData, int requestLength) throws IllegalArgumentException {
        String request;
        try {
            request = new String(requestData, 0, requestLength);
        } catch (IndexOutOfBoundsException e) {
            throw new IllegalArgumentException("");
        }
        this.request = request;

        String[] requestParts = request.split("\n");

        String[] firstLineParts = requestParts[0].split(" ");
        if (firstLineParts.length < 3) {
            throw new IllegalArgumentException("Invalid request data: \n" + request);
        }
        this.method = firstLineParts[0];

        String URI = firstLineParts[1].trim();
        this.absoluteUri = URI;
        URI = URI.replace("https://", "").replace("http://", "");
        int index = URI.indexOf("/");
        this.pathUri = index > -1 ? URI.substring(index) : "/";

        this.protocol = firstLineParts[2].split("/")[0];

        String hostParameter = Arrays.stream(requestParts)
                .filter(str -> str.startsWith("Host:"))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Host parameter missing: \n" + this.request));

        hostParameter = hostParameter.substring(hostParameter.indexOf(":") + 2).trim();
        if (hostParameter.contains(":")) {
            this.host = hostParameter.substring(0, hostParameter.indexOf(":"));
            this.port = Integer.parseInt(hostParameter.substring(hostParameter.indexOf(":") + 1).trim());
        } else {
            this.host = hostParameter;
            this.port = protocol.equalsIgnoreCase("HTTP") ? 80 : 443;
        }
    }

    public String getProxyModifiedRequest() {
        String request = this.request.replaceAll("Proxy-Connection:.*\r\n", "");
        return request.replaceFirst(absoluteUri, pathUri);
    }
}

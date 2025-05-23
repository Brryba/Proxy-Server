package service;

import lombok.Getter;
import model.Response;

import java.util.*;

public class ResponseMapper {
    private ResponseMapper() {}

    @Getter
    private static ResponseMapper instance = new ResponseMapper();

    private static final int MAX_AGE = 3600;

    public Response toResponseModel(byte[] responseArr) {
        String response = new String(responseArr);
        Map<String, String> headersMap = parsHeadersMap(response);

        String connectionType = headersMap.get("cache-control");
        long ttl = -1;
        if (connectionType != null) {
            List<String> cache = new ArrayList<>(List.of(connectionType.split(",")));
            cache.replaceAll(String::trim);
            if (!cache.contains("public") && cache.stream().noneMatch(c -> c.startsWith("max-age="))) {
                return null;
            }
            ttl = parseTTl(cache);
        }

        return new Response(responseArr, ttl == -1 ? MAX_AGE : ttl);
    }

    private long parseTTl(List<String> cacheParams) {
        long ttl = -1;
        for (String param : cacheParams) {
            if (param.startsWith("max-age=")) {
                ttl = Long.parseLong(param.replace("max-age=", ""));
            }
            if (param.startsWith("s-maxage=")) {
                ttl = Long.parseLong(param.replace("s-maxage=", ""));
                break;
            }
        }
        return ttl == -1 ? MAX_AGE : ttl;
    }

    private Map<String, String> parsHeadersMap(String response) {
        response = response.substring(0, response.indexOf("\r\n\r\n"));
        Map<String, String> headersMap = new HashMap<>();
        for (String line : response.split("\r\n")) {
            if (line.contains(":")) {
                headersMap.put(line.substring(0, line.indexOf(":")).toLowerCase(), line.substring(line.indexOf(":") + 1));
            }
        }
        return headersMap;
    }
}

package connection_handler;

import config.ProxyConfig;
import model.HttpRequestInfo;
import service.ResponseCacheService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RequestResponseHandler {
    private final ResponseCacheService responseCacheService;
    private final Deque<String> requests;
    private final ExecutorService pool;
    private final boolean isHttp;

    public RequestResponseHandler(ExecutorService pool, boolean isHttp) {
        this.responseCacheService = ResponseCacheService.getInstance();
        this.requests = new LinkedList<>();
        this.pool = pool;
        this.isHttp = isHttp;
    }

    public void addRequest(String request) {
        requests.add(request);
    }

    public void handleConnection(Socket clientSocket, Socket serverSocket) {
        pool.execute(() -> handleClientToServer(clientSocket, serverSocket));
        handleServerToClient(clientSocket, serverSocket);
    }

    private void handleClientToServer(Socket clientSocket, Socket serverSocket) {
        try {
            while (true) {
                byte[] buf = new byte[ProxyConfig.BUFFER_SIZE];
                int bytesRead = clientSocket.getInputStream().read(buf);
                boolean canBeFromCache = false;
                try {
                    HttpRequestInfo r = new HttpRequestInfo();
                    r.setRequestData(buf, bytesRead);
                    requests.addFirst(r.getHost() + r.getPathUri());
                    canBeFromCache = r.isCanBeFromCache();
                    if (this.isHttp) {
                        String improved = logAndUpdateRequestInfo(r);
                        buf = improved.getBytes();
                        bytesRead = buf.length;
                    } else {
                        System.out.println(r.getRequest());
                    }
                } catch (Exception _) {
                }
                if (bytesRead == -1) {
                    closeConnections(clientSocket, serverSocket);
                    break;
                }

                if (responseCacheService.containsResponse(requests.getLast())) {
                    if (canBeFromCache) {
                        writeCachedRequestToClient(clientSocket);
                        System.out.println(requests.getLast() + " LOADED FROM CACHE");
                        requests.removeLast();
                    } else {
                        serverSocket.getOutputStream().write(buf, 0, bytesRead);
                        serverSocket.getOutputStream().flush();
                        System.out.println(requests.getLast() + " FOUND IN CACHE BUT WAS NOT LOADED");
                    }
                } else {
                    serverSocket.getOutputStream().write(buf, 0, bytesRead);
                    serverSocket.getOutputStream().flush();
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private void handleServerToClient(Socket clientSocket, Socket serverSocket) {
        try {
            ByteArrayOutputStream multiPacketsBuffer = null;
            int contentLengthRemained = -1;
            boolean isChunkedResponse = false;

            while (true) {
                byte[] buf = new byte[ProxyConfig.BUFFER_SIZE];
                int bytesRead = serverSocket.getInputStream().read(buf);
                if (bytesRead == -1) {
                    closeConnections(clientSocket, serverSocket);
                    break;
                }

                clientSocket.getOutputStream().write(buf, 0, bytesRead);
                clientSocket.getOutputStream().flush();

                if (contentLengthRemained > -1) {
                    if (multiPacketsBuffer == null) {
                        multiPacketsBuffer = new ByteArrayOutputStream();
                    }
                    contentLengthRemained = cacheResponseWithContentLength(buf, bytesRead, contentLengthRemained, multiPacketsBuffer);
                    continue;
                }

                String beginning = new String(buf, 0, 5);
                if (contentLengthRemained == -1 && !isChunkedResponse && !beginning.equals("HTTP/")) {
                    continue;
                }

                logResponse(new String(buf, 0, bytesRead), requests.getLast());

                contentLengthRemained = getContentLength(buf, bytesRead);

                if (contentLengthRemained > 0) {
                    multiPacketsBuffer = new ByteArrayOutputStream();
                    contentLengthRemained = cacheResponseWithContentLength(buf, bytesRead,
                            contentLengthRemained + getHeadersLength(buf, bytesRead), multiPacketsBuffer);
                } else {
                    if (!isChunkedResponse) {
                        multiPacketsBuffer = null;
                        isChunkedResponse = isChunked(buf, bytesRead);
                        if (isChunkedResponse) {
                            multiPacketsBuffer = new ByteArrayOutputStream();
                        }
                    }

                    isChunkedResponse = cacheResponseAndSetChunked(buf, bytesRead, isChunkedResponse, multiPacketsBuffer);
                }
            }
        } catch (Exception e) {
            System.out.println("Connection closed by server");
        }
    }

    private void writeCachedRequestToClient(Socket clientSocket) {
        byte[] serviceResponse = responseCacheService.getResponse(requests.getLast());
        int remainedLength = serviceResponse.length, bytesRead = 0;
        final int TLS_MAX_LENGTH = 16384;
        try {
            do {
                if (remainedLength > TLS_MAX_LENGTH) {
                    byte[] temp = Arrays.copyOfRange(serviceResponse, bytesRead, bytesRead + TLS_MAX_LENGTH);
                    bytesRead += TLS_MAX_LENGTH;
                    remainedLength -= TLS_MAX_LENGTH;
                    clientSocket.getOutputStream().write(temp, 0, TLS_MAX_LENGTH);
                    clientSocket.getOutputStream().flush();
                } else {
                    clientSocket.getOutputStream().write(serviceResponse, bytesRead, remainedLength);
                    clientSocket.getOutputStream().flush();
                    remainedLength = 0;
                }
            } while (remainedLength > 0);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    private int cacheResponseWithContentLength(byte[] buf, int bytesRead, int contentLengthRemained, ByteArrayOutputStream contentBuffer) {
        int bytesToWrite = Math.min(bytesRead, contentLengthRemained);
        contentBuffer.write(buf, 0, bytesToWrite);

        if (bytesToWrite >= contentLengthRemained) {
            String requestName = requests.removeLast();
            CompletableFuture.runAsync(() ->
                    responseCacheService.cacheResponse(requestName, contentBuffer.toByteArray()));
            return -1;
        }
        return contentLengthRemained - bytesToWrite;
    }

    private int getHeadersLength(byte[] response, int length) {
        String responseStr = new String(response, 0, Math.min(length, 2048));
        return responseStr.indexOf("\r\n\r\n") + 4;
    }

    private int getContentLength(byte[] response, int length) {
        String headers = new String(response, 0, Math.min(length, 2048));
        Pattern pattern = Pattern.compile("Content-Length:\\s*(\\d+)");
        Matcher matcher = pattern.matcher(headers);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return -1;
    }

    private boolean cacheResponseAndSetChunked(byte[] response, int responseLength, boolean isChunked, ByteArrayOutputStream chunkedBuffer) {
        if (isChunked) {
            chunkedBuffer.write(response, 0, responseLength);

            if (isEndOfChunked(response, responseLength)) {
                byte[] fullData = chunkedBuffer.toByteArray();
                String requestName = requests.removeLast();
                CompletableFuture.runAsync(() ->
                        responseCacheService.cacheResponse(requestName, fullData));
                return false;
            }
        } else {
            byte[] finalResponseData = Arrays.copyOf(response, responseLength);
            String requestName = requests.removeLast();
            CompletableFuture.runAsync(() ->
                    responseCacheService.cacheResponse(requestName, finalResponseData));
            return false;
        }
        return true;
    }

    private boolean isChunked(byte[] response, int length) {
        String headers = new String(response, 0, Math.min(length, 2048));
        return headers.contains("Transfer-Encoding: chunked");
    }

    private boolean isEndOfChunked(byte[] data, int dataLength) {
        if (dataLength < 5) return false;
        int start = Math.max(0, dataLength - 7);
        String tail = new String(data, start, dataLength - start);
        return tail.contains("0\r\n\r\n");
    }

    private void closeConnections(Socket... sockets) {
        for (Socket socket : sockets) {
            try {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
            } catch (IOException e) {
                System.err.println("Error closing socket: " + e.getMessage());
            }
        }
    }

    private void logResponse(String response, String uri) {
        if (!response.startsWith("HTTP")) {
            return;
        }
        int emptyLineIndex = response.indexOf("\r\n\r\n");
        System.out.println("Response from " + uri + ":");
        if (emptyLineIndex == -1) {
            System.out.println(response);
        } else {
            System.out.println(response.substring(0, emptyLineIndex));
        }
        System.out.println("\n");
    }

    static String logAndUpdateRequestInfo(HttpRequestInfo request) {
        System.out.println("Original request: \n" + request.getRequest());
        String improvedRequest = request.getProxyModifiedRequest();
        System.out.println("Proxy-modified request: \n" + improvedRequest);
        return improvedRequest;
    }
}
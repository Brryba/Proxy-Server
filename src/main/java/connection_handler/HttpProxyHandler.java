package connection_handler;

import model.HttpRequestInfo;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.ExecutorService;

import static connection_handler.RequestResponseHandler.logAndUpdateRequestInfo;

public class HttpProxyHandler {
    private final RequestResponseHandler requestResponseHandler;

    public HttpProxyHandler(ExecutorService pool) {
        this.requestResponseHandler = new RequestResponseHandler(pool, true);
    }

    public void startHTTPConnection(Socket clientSocket, HttpRequestInfo requestInfo) {
        try {
            Socket httpSocket = new Socket(requestInfo.getHost(), requestInfo.getPort());
            String improvedRequest = logAndUpdateRequestInfo(requestInfo);
            httpSocket.getOutputStream().write(improvedRequest.getBytes(), 0, improvedRequest.length());
            httpSocket.getOutputStream().flush();

            requestResponseHandler.addRequest(requestInfo.getHost() + requestInfo.getPathUri());
            requestResponseHandler.handleConnection(clientSocket, httpSocket);
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }
}

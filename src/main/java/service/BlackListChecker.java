package service;

import config.ProxyConfig;
import model.HttpRequestInfo;

import java.io.IOException;
import java.net.Socket;

public class BlackListChecker {
    private BlackListChecker() {
    }

    private static final String response403 = """
            HTTP/1.1 403 Forbidden
            Content-Type: text/html
            Connection: close
            
            <!DOCTYPE html>
                     <html>
                     <head><title>Access Denied By Proxy</title></head>
                     <body>
                         <h1>403 Forbidden</h1>
                         <p>This site is blocked by the proxy.</p>
                         <p>You can change it via config.yml file</p>
                     </body>
                     </html>
            """.replace("\n", "\r\n");

    public static boolean isBlackListed(Socket clientSocket, HttpRequestInfo requestInfo) {
        String host = requestInfo.getHost();
        String clearHost = host.replace("www.", "")
                .replace("http://", "")
                .replace("https://", "");
        if (ProxyConfig.blackList.stream()
                .anyMatch((domain) -> domain.equals(clearHost) ||
                domain.startsWith("*") && clearHost.endsWith(domain.substring(1)))) {
            try {
                clientSocket.getOutputStream().write(response403.getBytes());
                clientSocket.getOutputStream().flush();
                clientSocket.close();
            } catch (IOException _) {}
            return true;
        } else {
            return false;
        }
    }
}

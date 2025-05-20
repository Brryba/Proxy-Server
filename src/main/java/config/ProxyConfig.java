package config;

import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class ProxyConfig {
    public static final int BUFFER_SIZE = 1_000_000;
    public static int MAX_THREADS = 1000;
    public static int PORT = 54321;
    public static String HOST = "127.0.0.1";
    public static int BACKLOG = 10;
    public static String BLACKLIST_PATH = "config.yml";

    public enum HttpsMode {
        HTTPS_TUNNEL,
        HTTPS_MITM
    }

    public static HttpsMode httpsMode = HttpsMode.HTTPS_TUNNEL;
    public static Set<String> blackList;

    public void initialize() {
        Yaml yaml = new Yaml();
        try (InputStream in = Files.newInputStream(Path.of(BLACKLIST_PATH))) {
            Map<String, Object> data = yaml.load(in);
            String ymlMode = (String) data.get("https-mode");
            httpsMode = ymlMode.equals("mitm") ? HttpsMode.HTTPS_MITM : HttpsMode.HTTPS_TUNNEL;
            //noinspection unchecked
            blackList = new HashSet<>((List<String>) data.get("blacklist"));
        } catch (IOException e) {
            System.err.println("Error in config.yml file: " + e.getMessage());
        }
    }
}

package repository;

import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import lombok.Getter;

import java.time.LocalDateTime;

public class ResponseCacheRepository {
    private final RedisClient redisClient;
    private final StatefulRedisConnection<String, String> connection;
    private final RedisCommands<String, String> redisCommands;

    @Getter
    private static ResponseCacheRepository instance = new ResponseCacheRepository();

    private ResponseCacheRepository() {
        try {
            this.redisClient = RedisClient.create("redis://password@localhost:6379/");
            this.connection = redisClient.connect();
            this.redisCommands = connection.sync();
        } catch (Exception e) {
            System.err.println("Unable to connect to redis " + e.getMessage());
            throw e;
        }
    }

    public void addResponse(String uri, String response, int ttl, LocalDateTime lastModified, String eTag) {
        String name = "uri:" + uri;
        redisCommands.hset(name, "response", response);
        if (lastModified != null) {
            redisCommands.hset(name, "lastModified", lastModified.toString());
        }
        redisCommands.hset(name, "eTag", eTag);
        redisCommands.expire(name, ttl);
        try {
            Thread.sleep(6000);
        } catch (InterruptedException _) {}
    }
}
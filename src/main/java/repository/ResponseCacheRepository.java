package repository;

import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import model.Response;

import java.util.Arrays;

public class ResponseCacheRepository {
    private final RedisClient redisClient;
    private final StatefulRedisConnection<String, String> connection;
    private final RedisCommands<String, String> redisCommands;

    private static ResponseCacheRepository instance = new ResponseCacheRepository();

    public static ResponseCacheRepository getInstance() {
        if (instance == null) {
            instance = new ResponseCacheRepository();
        }
        return instance;
    }

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

    public void addResponse(String uri, Response response) {
        String name = "uri:" + uri;
        redisCommands.hset(name, "response", Arrays.toString(response.getResponseBytes()));
        redisCommands.expire(name, response.getTimeToLive());
    }

    public byte[] readResponse(String absoluteUri) {
        String name = "uri:" + absoluteUri;
        String response = redisCommands.hget(name, "response");
        response = response.substring(1, response.length() - 1);
        String[] nums = response.split(",");
        byte[] responseBytes = new byte[nums.length];
        for (int i = 0; i < nums.length; i++) {
            responseBytes[i] = Byte.parseByte(nums[i].trim());
        }
        return responseBytes;
    }

    public boolean containsResponse(String absoluteUri) {
        String name = "uri:" + absoluteUri;
        return redisCommands.hget(name, "response") != null;
    }
}
package service;

import lombok.Getter;
import repository.ResponseCacheRepository;

public class ResponseCacheService {
    private ResponseCacheService() {}

    private final ResponseCacheRepository repository;

    {
        repository = ResponseCacheRepository.getInstance();
    }

    @Getter
    private static ResponseCacheService instance = new ResponseCacheService();

    public void cacheResponse(String response) {
        repository.addResponse("www.mirostat.by/", response, 60, null, "");
    }
}

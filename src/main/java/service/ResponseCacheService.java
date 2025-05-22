package service;

import lombok.Getter;
import model.Response;
import repository.ResponseCacheRepository;

public class ResponseCacheService {
    private ResponseCacheService() {}

    private final ResponseCacheRepository repository;
    private final ResponseMapper mapper;

    {
        repository = ResponseCacheRepository.getInstance();
        mapper = ResponseMapper.getInstance();
    }

    static {
        instance = new ResponseCacheService();
    }

    @Getter
    private static final ResponseCacheService instance;

    public void cacheResponse(String absoluteUri, byte[] response) {
        Response responseModel = mapper.toResponseModel(response);
        if (responseModel == null) return;
        repository.addResponse(absoluteUri, responseModel);
    }

    public byte[] getResponse(String absoluteUri) {
        return repository.readResponse(absoluteUri);
    }

    public boolean containsResponse(String absoluteUri) {
        return repository.containsResponse(absoluteUri);
    }
}

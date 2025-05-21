package model;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class Response {
    String responseText;
    int timeToLive;
    String eTag;
    LocalDateTime lastModified;
}

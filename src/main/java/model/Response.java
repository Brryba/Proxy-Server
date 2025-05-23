package model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
public class Response {
    byte[] responseBytes;
    long timeToLive;
}

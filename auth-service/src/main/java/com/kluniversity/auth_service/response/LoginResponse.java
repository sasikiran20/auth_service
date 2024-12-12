package com.kluniversity.auth_service.response;

public record LoginResponse(String token, long expiry) {
}

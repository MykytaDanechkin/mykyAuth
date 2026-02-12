package com.mykyda.mykyauth.exception;

public class AccessTokenValidationException extends RuntimeException {
    public AccessTokenValidationException(String message) {
        super(message);
    }
}

package com.mykyda.mykyauth.exception;

public class UserExistsException extends Throwable {
    public UserExistsException(String message) {
        super(message);
    }
}

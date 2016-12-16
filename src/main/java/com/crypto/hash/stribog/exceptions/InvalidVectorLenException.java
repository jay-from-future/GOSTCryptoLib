package com.crypto.hash.stribog.exceptions;

/**
 * Created by Admin on 08.09.2015.
 */
public class InvalidVectorLenException extends RuntimeException {
    public InvalidVectorLenException() {
    }

    public InvalidVectorLenException(String message) {
        super(message);
    }

    public InvalidVectorLenException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidVectorLenException(Throwable cause) {
        super(cause);
    }

    public InvalidVectorLenException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}

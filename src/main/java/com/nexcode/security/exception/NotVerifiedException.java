package com.nexcode.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class NotVerifiedException extends RuntimeException {
	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public NotVerifiedException(String message) {
		super(message);
	}

	public NotVerifiedException(String message, Throwable cause) {
		super(message, cause);
	}
}

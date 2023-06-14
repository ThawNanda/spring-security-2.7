package com.nexcode.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class IncorrectPasswordException extends RuntimeException{

	private static final long serialVersionUID = 3020156485817601802L;

	public IncorrectPasswordException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	public IncorrectPasswordException(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}
	
}

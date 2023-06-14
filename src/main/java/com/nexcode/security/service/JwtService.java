package com.nexcode.security.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;

public interface JwtService {

	String extractUsername(String jwt);

	boolean isTokenValid(String jwt, UserDetails userDetails);

	Claims getClaims(String jwt);

	String generateToken(Authentication authentication);

}

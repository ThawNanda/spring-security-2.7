package com.nexcode.security.service.impl;

import java.util.Date;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import com.nexcode.security.exception.BadRequestException;
import com.nexcode.security.model.request.LoginRequest;
import com.nexcode.security.model.response.AuthenticationResponse;
import com.nexcode.security.service.AuthService;
import com.nexcode.security.service.JwtService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

	private final AuthenticationManager authenticationManager;

	private final JwtService jwtService;

	@Override
	public AuthenticationResponse authenticate(LoginRequest request) {

		Date expiredAt = new Date((new Date()).getTime() + 86400 * 1000);

		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

		if (authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
			String jwt = jwtService.generateToken(authentication);
			return new AuthenticationResponse(jwt, expiredAt.toInstant().toString());

		} else if (authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER"))) {
			String jwt = jwtService.generateToken(authentication);
			return new AuthenticationResponse(jwt, expiredAt.toInstant().toString());
		} else {
			throw new BadRequestException("Email or Password is incorrect!");
		}
	}
}

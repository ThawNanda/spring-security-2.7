package com.nexcode.security.service;

import com.nexcode.security.model.request.LoginRequest;
import com.nexcode.security.model.response.AuthenticationResponse;

public interface AuthService {

	AuthenticationResponse authenticate(LoginRequest request);

}

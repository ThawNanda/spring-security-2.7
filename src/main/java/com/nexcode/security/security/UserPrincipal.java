package com.nexcode.security.security;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nexcode.security.model.entity.User;

public class UserPrincipal implements UserDetails {

	private static final long serialVersionUID = 1L;

	private Long id;

	private String username;

	@JsonIgnore
	private String password;

	@JsonIgnore
	private boolean lock;

	public Collection<? extends GrantedAuthority> authorities;

	public UserPrincipal(Long id, String username, String password,
			Collection<? extends GrantedAuthority> authorities) {
		this.id = id;
		this.username = username;
		this.password = password;
		this.authorities = authorities;
	}

	public static UserPrincipal build(User user) {
		List<GrantedAuthority> authorities = user.getRoles().stream()
				.map(role -> new SimpleGrantedAuthority(role.getName().name())).collect(Collectors.toList());
		// GrantedAuthority authority = new
		// SimpleGrantedAuthority(user.getRole().getRoleName().name());
		return new UserPrincipal(user.getId(), user.getUsername(), user.getPassword(), authorities);
	}

	public Long getId() {
		return id;
	}

	public String getName() {
		return username;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public String getPassword() {
		return password;
	}

	public boolean isLock() {
		return lock;
	}

	public void setLock(boolean lock) {
		this.lock = lock;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		if (this.lock == true) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;

	}

	@Override
	public boolean isEnabled() {
		if (this.lock == true) {
			return false;
		}
		return true;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;

		UserPrincipal user = (UserPrincipal) o;
		return Objects.equals(id, user.id);
	}

}
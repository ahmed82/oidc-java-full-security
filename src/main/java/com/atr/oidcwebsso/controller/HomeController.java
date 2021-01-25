package com.atr.oidcwebsso.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
	
	@GetMapping("/hi")
	public String home() {
		
		return "test";
	}
	
	@GetMapping("/oidc-principal")
	public OidcUser getOidcUserPrincipal(
	  @AuthenticationPrincipal OidcUser principal) {
	    return principal;
	}

}

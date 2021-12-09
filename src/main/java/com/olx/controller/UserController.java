package com.olx.controller;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

import com.olx.dto.AuthenticationRequest;
import com.olx.dto.RegisterUser;
import com.olx.entity.UserEntity;
import com.olx.security.JwtUtil;
import com.olx.service.UserService;

import io.swagger.annotations.ApiOperation;

@RestController
@RequestMapping("olx/user")
public class UserController {
	
	@Autowired
	AuthenticationManager  authenticationManager;
	@Autowired
	UserDetailsService userDetailsService;
	@Autowired
	JwtUtil jwtUtil;
	
	@PostMapping(value="/authenticate",
			consumes= {MediaType.APPLICATION_JSON_VALUE,MediaType.APPLICATION_XML_VALUE},
			produces= {MediaType.APPLICATION_JSON_VALUE,MediaType.APPLICATION_XML_VALUE})
			public ResponseEntity<String> createNewUsers(@RequestBody AuthenticationRequest authenticationRequest) {
		
		try {
			this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUserName(), authenticationRequest.getPassword()));
						
		}catch(BadCredentialsException ex) {
			
			return new ResponseEntity<String>(ex.getMessage(),HttpStatus.BAD_REQUEST);
		}
		//login success
		
		UserDetails userDetails=userDetailsService.loadUserByUsername(authenticationRequest.getUserName());
		String jwttoken=jwtUtil.generateToken(userDetails);
		String name=jwttoken.toString();
		return new ResponseEntity<String>(name, HttpStatus.OK);
			}
	
	
@GetMapping(value="/validate/token",
			consumes= {MediaType.APPLICATION_JSON_VALUE,MediaType.APPLICATION_XML_VALUE},
			produces= {MediaType.APPLICATION_JSON_VALUE,MediaType.APPLICATION_XML_VALUE})
public ResponseEntity<Boolean> validateToken(@RequestHeader("Authorization")String authToken){
	
	boolean isTokenValid=false;
	try {
		String jwtToken=authToken.substring(7, authToken.length());
		String userName=jwtUtil.extractUsername(jwtToken);
		UserDetails userDetails=userDetailsService.loadUserByUsername(userName);
		isTokenValid=jwtUtil.validateToken(jwtToken, userDetails);
	    }catch(Exception ex) {
		return new ResponseEntity<Boolean>(false,HttpStatus.BAD_REQUEST);
	}
	return new ResponseEntity<Boolean>(isTokenValid, HttpStatus.OK);
	}
	
	

	
}

package com.olx.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Autowired
	UserDetailsService userDetailsService;
	
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
	 http.csrf().disable().authorizeRequests()
	 .antMatchers("/user").hasAnyRole("USERS","ADMIN")
	 .antMatchers("/admin").hasRole("ADMIN")
	 .antMatchers("olx/user/authenticate").permitAll()
	 .and().formLogin();
	 
	}
	
	//For Authentication
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception{ 
		
//		auth.inMemoryAuthentication()
//		.withUser("cnu").password(passwordEncoder.encode("cnu12345")).roles("ADMIN")
//		.and()
//		.withUser("kaleem").password(passwordEncoder.encode("kaleem12345")).roles("USER");
		
		//database Authentication
		auth.userDetailsService(userDetailsService);
		
		
		
	}
	
	@Bean
	public AuthenticationManager getAuthenticationManager() throws Exception{
		
		return super.authenticationManager();
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
}

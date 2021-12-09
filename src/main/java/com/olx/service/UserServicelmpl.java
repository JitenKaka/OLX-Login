package com.olx.service;


import org.springframework.stereotype.Service;
import org.modelmapper.ModelMapper;
import org.modelmapper.TypeMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.olx.dto.RegisterUser;
import com.olx.entity.UserEntity;
import com.olx.repo.UserRepo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User;
@Service
public class UserServicelmpl implements UserService{
	@Autowired
	private  UserRepo userRepo;
	@Autowired
private PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		List<UserEntity> userEntityList =  userRepo.findByUserName(username);
		if(userEntityList.size() == 0) {
			throw new UsernameNotFoundException(username);
		}
		
		UserEntity userEntity = userEntityList.get(0);
		List<GrantedAuthority> autorities =  new ArrayList<GrantedAuthority>();
		autorities.add(new SimpleGrantedAuthority(userEntity.getRoles()));
		
		User user = new User(userEntity.getUserName(), passwordEncoder.encode(userEntity.getPassword()),autorities);
		
		return user;
	}


	

}

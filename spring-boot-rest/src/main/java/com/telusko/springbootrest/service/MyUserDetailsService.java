package com.telusko.springbootrest.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.telusko.springbootrest.model.User;
import com.telusko.springbootrest.model.UserPrincipal;
import com.telusko.springbootrest.repo.UserRepo;


@Service
public class MyUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepo repo;
	
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println(">>> Username received during login: " + username);
	User user= repo.findByUsername(username);
	
	if (user==null) {
		System.out.println("User 404");
		throw new UsernameNotFoundException("User 404");
	}
        System.out.println(">>> Password stored in DB: " + user.getPassword());
        System.out.println("UserPrincipal password: " + new UserPrincipal(user).getPassword());
		 return new UserPrincipal(user);
	}

}

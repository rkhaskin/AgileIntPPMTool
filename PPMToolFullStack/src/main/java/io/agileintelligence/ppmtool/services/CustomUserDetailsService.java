package io.agileintelligence.ppmtool.services;

import static java.util.Collections.emptyList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//import io.agileintelligence.ppmtool.domain.User;
import io.agileintelligence.ppmtool.repositories.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService
{

	@Autowired
	private UserRepository userRepository;

	/*
	 * returns UseerDetails, which is implemented by the User class. Used by
	 * authentication manager builder
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
	{
		io.agileintelligence.ppmtool.domain.User user = userRepository.findByUsername(username);
		if (user == null)
			new UsernameNotFoundException("User not found");
		return new User(user.getUsername(), user.getPassword(), emptyList());
	}


}

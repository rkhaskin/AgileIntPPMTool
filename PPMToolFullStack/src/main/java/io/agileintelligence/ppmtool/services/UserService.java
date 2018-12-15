package io.agileintelligence.ppmtool.services;

import io.agileintelligence.ppmtool.domain.User;
import io.agileintelligence.ppmtool.exceptions.UsernameAlreadyExistsException;
import io.agileintelligence.ppmtool.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService
{

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public User saveUser(User newUser)
	{

		try
		{
			// encrypt the password
			newUser.setPassword(bCryptPasswordEncoder.encode(newUser.getPassword()));
			// Username has to be unique (exception)
			newUser.setUsername(newUser.getUsername());
			// Make sure that password and confirmPassword match
			// We don't persist or show the confirmPassword
			newUser.setConfirmPassword("");
			return userRepository.save(newUser);

		} catch (Exception e)
		{
			throw new UsernameAlreadyExistsException("Username '" + newUser.getUsername() + "' already exists");
		}

	}
	
	@Transactional
	public User loadUserById(Long id)
	{
		User user = userRepository.getById(id);
		if (user == null)
			new UsernameNotFoundException("User not found");
		return user;

	}	

}

package io.agileintelligence.ppmtool.exceptions;

/*
 * this class contains a message to the client that the user is not authenticated. For better security, do not tell them that the username is OK, it's just the password which is wrong.
 * Always say that both are incorrect to prevent attacks and not give them hints
 */
public class InvalidLoginResponse
{
	private String username;
	private String password;

	public InvalidLoginResponse()
	{
		this.username = "Invalid Username";
		this.password = "Invalid Password";
	}

	public String getUsername()
	{
		return username;
	}

	public void setUsername(String username)
	{
		this.username = username;
	}

	public String getPassword()
	{
		return password;
	}

	public void setPassword(String password)
	{
		this.password = password;
	}
}

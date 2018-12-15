package io.agileintelligence.ppmtool.security;

import com.google.gson.Gson;
import io.agileintelligence.ppmtool.exceptions.InvalidLoginResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
 * The purpose of this class is to create a custom message that will be sent to the client un case the authentication failed.
 */

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint
{

	@Override
	public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			AuthenticationException e) throws IOException, ServletException
	{

		InvalidLoginResponse loginResponse = new InvalidLoginResponse();
		// convert object to json
		String jsonLoginResponse = new Gson().toJson(loginResponse);

		httpServletResponse.setContentType("application/json");
		httpServletResponse.setStatus(401);
		httpServletResponse.getWriter().print(jsonLoginResponse);

	}
}

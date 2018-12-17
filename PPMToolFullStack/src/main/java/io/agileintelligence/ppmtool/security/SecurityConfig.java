package io.agileintelligence.ppmtool.security;

import static io.agileintelligence.ppmtool.security.SecurityConstants.H2_URL;
import static io.agileintelligence.ppmtool.security.SecurityConstants.SIGN_UP_URLS;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import io.agileintelligence.ppmtool.services.CustomUserDetailsService;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, // this setting allows to set method-based security. It will be based
													// on the roles...
		jsr250Enabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter
{

	@Autowired
	private JwtAuthenticationEntryPoint unauthorizedHandler;

	@Autowired
	private CustomUserDetailsService customUserDetailsService;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@Override
	protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception
	{
		authenticationManagerBuilder.userDetailsService(customUserDetailsService)
				.passwordEncoder(bCryptPasswordEncoder);
	}

	@Override
	@Bean(BeanIds.AUTHENTICATION_MANAGER)
	protected AuthenticationManager authenticationManager() throws Exception
	{
		return super.authenticationManager();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.config.annotation.web.configuration.
	 * WebSecurityConfigurerAdapter#configure(org.springframework.security.config.
	 * annotation.web.builders.HttpSecurity) overrides a default implementation of
	 * HttpSecurity. As we have apis here, this is how we secure them
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception
	{
		http.cors().and().csrf().disable() // these two are about attacks (cross-site and cross-origin resourse sharing
											// as we are using jwt and it will prevent both)
		
		// show a custom error message instead of a default 401 response when login is not successful. For example, when trying to login with
		// bad username
		.exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and() 
		// do not save sessions or cookies. All done with tokens
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		// To enable H2 Database
		.and().headers().frameOptions().sameOrigin() 
		.and().authorizeRequests()
		.antMatchers("/", "/favicon.ico", "/**/*.png", "/**/*.gif", "/**/*.svg", "/**/*.jpg", "/**/*.html",
				"/**/*.css", "/**/*.js")
		// permit all of these requests. Do not use security for clients like Thymeleaf, Spring MVC, JSP, etc.		
		.permitAll() 
		.antMatchers(SIGN_UP_URLS).permitAll() // allow new users to register or see the login screen
				.antMatchers(H2_URL).permitAll()
				.anyRequest().authenticated() // anything other than above needs
																				// authentication
        // run jwtAuthenticationFilter for all other requests.
//		http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
		.anyRequest().authenticated().and().addFilter(new JWTAuthenticationFilter(authenticationManager()))
		.addFilter(new JWTAuthorizationFilter(authenticationManager()));
		
	}
	
	/*
	@Bean
	CorsConfigurationSource corsConfigurationSource()
	{
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
		return source;
	}
	*/
	
	
	@Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        configuration.setAllowedMethods(Arrays.asList("HEAD",
                "GET", "POST", "PUT", "DELETE", "PATCH"));
        // setAllowCredentials(true) is important, otherwise:
        // The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'.
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(Arrays.asList("Authorization"));
        // setAllowedHeaders is important! Without it, OPTIONS preflight request
        // will fail with 403 Invalid CORS request
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    
    	
}

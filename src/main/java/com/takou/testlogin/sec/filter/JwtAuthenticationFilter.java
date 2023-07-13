package com.takou.testlogin.sec.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.takou.testlogin.sec.config.JWTUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        System.out.println(username);
        System.out.println(password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("bien dans la methode connecté");
        User user = (User) authResult.getPrincipal();
        Algorithm algo1 = Algorithm.HMAC256(JWTUtil.SECRET);
        // creation du token et sa structure
        String jwtAccesToken = JWT.create()
                .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+ JWTUtil.EXPIRE_ACCESS_TOKEN))
                                .withIssuer(request.getRequestURL().toString())
                                        .withClaim("roles", user.getAuthorities().stream().map(ga ->ga.getAuthority()).collect(Collectors.toList()))
                                                .sign(algo1);
        // envoi du token dans le header avec l'attribut Authorization
        //response.setHeader("Authorization", jwtAccesToken);

        String jwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+ 15*60*1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algo1);
        Map<String, String> idToken = new HashMap<>();
        idToken.put("access-token", jwtAccesToken);
        idToken.put("refresh-token", jwtRefreshToken);
        response.setHeader("Authorization", jwtRefreshToken);

        response.setContentType("application/jason");
        new ObjectMapper().writeValue(response.getOutputStream(), idToken);

        //super.successfulAuthentication(request, response, chain, authResult);
    }
}

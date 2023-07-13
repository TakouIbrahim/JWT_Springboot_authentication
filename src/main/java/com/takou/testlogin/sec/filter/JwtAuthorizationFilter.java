package com.takou.testlogin.sec.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.takou.testlogin.sec.config.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorisationToken = request.getHeader(JWTUtil.AUTH_HEADER);
        if(request.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(request, response);
        }else {
            // vérifie si le token existe et commence bien par bearer
            if (authorisationToken!= null && authorisationToken.startsWith(JWTUtil.PREFIX)){
                try {
                    String jwt = authorisationToken.substring(JWTUtil.PREFIX.length());
                    Algorithm algo = Algorithm.HMAC256(JWTUtil.SECRET);
                    JWTVerifier jwtVerifier = JWT.require(algo).build();
                    DecodedJWT decodedJWT  = jwtVerifier.verify(jwt);
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for(String role : roles){
                        authorities.add(new SimpleGrantedAuthority(role));
                    }
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);

                    //authentification de l'utilisateur
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    // ici on dit que tu peut passer (au suivant)
                    filterChain.doFilter(request, response);

                } catch (Exception e){
                    response.setHeader("error-message", e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            } else {
                // tu passe mais ici, tu n'est pas reconnu donc spring va vérifier si la ressource demander à besoin d'authorisation ou pas
                filterChain.doFilter(request, response);
            }
        }


    }
}

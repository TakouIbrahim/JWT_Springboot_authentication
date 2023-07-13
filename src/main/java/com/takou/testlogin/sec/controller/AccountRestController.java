package com.takou.testlogin.sec.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.takou.testlogin.sec.config.JWTUtil;
import com.takou.testlogin.sec.entities.AppRole;
import com.takou.testlogin.sec.entities.AppUser;
import com.takou.testlogin.sec.service.AccountService;
import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {

    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    AppUser saveUser (@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    AppRole saveRole (@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")
    public void addRoleToUser (@RequestBody RoleUserForm roleUserForm){
         accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
    }

    @GetMapping(path = "/refreshToken")
    public  void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception{
        String authenticationToken = request.getHeader(JWTUtil.AUTH_HEADER);
        if(authenticationToken!=null && authenticationToken.startsWith(JWTUtil.PREFIX)){
            try{
                String jwt = authenticationToken.substring(JWTUtil.PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                String username = decodedJWT.getSubject();
                AppUser appUser = accountService.loadUserByUsername(username);
                // creation du token et sa structure
                String jwtAccesToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+ JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getAppRoles().stream().map(r ->r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String, String > idToken = new HashMap<>();
                idToken.put("Refresh-token", jwtAccesToken);
                idToken.put("access-token", jwt);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(), idToken);

            }catch (Exception e){
                //response.setHeader("error-message", e.getMessage());
                //response.sendError(HttpServletResponse.SC_FORBIDDEN);
                throw e;
            }
        } else {
            throw  new RuntimeException("Refresh token required !!!!");
        }

    }

    @GetMapping(path = "/profile")
    @PostAuthorize("hasAuthority('USER')")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());
    }

}

@Data
class RoleUserForm{
    private String username;


    private  String roleName;
}

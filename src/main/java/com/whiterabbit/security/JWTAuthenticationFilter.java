package com.whiterabbit.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.whiterabbit.entities.AppUser;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("enter in JWTAuthenticationFilter method attemptAuthentication");
        try {
            //déserialization
            AppUser appUser = new ObjectMapper().readValue(request.getInputStream(), AppUser.class);
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(appUser.getUsername(),appUser.getPassword()));
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("enter in JWTAuthenticationFilter method successfulAuthentication");
        //recup user authentifié
        User userSpring=(User) authResult.getPrincipal();
        //recup roles
        List<String> roles=new ArrayList<>();
        userSpring.getAuthorities().forEach(role->{
            roles.add(role.getAuthority());
        });

        //creation du token JWT
        String jwt= JWT.create()
                .withIssuer(request.getRequestURI())                                        //nom de l'appi qui à générée le token
                .withSubject(userSpring.getUsername())                                      //user login
                .withArrayClaim("roles", roles.toArray(new String[roles.size()]))     //tableau des roles du user
                .withExpiresAt(new Date(System.currentTimeMillis()+SecurityParams.EXPIRATION))             //expiration du token 10 jours
                .sign(Algorithm.HMAC256(SecurityParams.SECRET));

        //ajout tokken au header de la reponse
        response.addHeader(SecurityParams.JWT_HEADER_NAME, jwt);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        //ajout tokken au body de la reponse
        response.getWriter().write(
                "{\"" + SecurityParams.JWT_HEADER_NAME + "\":\"" + SecurityParams.HEADER_PREFIX+jwt + "\""
        );
        //ajouter user infos dans la reponse

        response.getWriter().write(
                ",\"username\":\"" + userSpring.getUsername() + "\""
        );

        int cpt = 0;
        for (String role : roles) {
            cpt++;
            if(cpt == 1){
                response.getWriter().write(
                        ",\"Roles\":[");
            }

            response.getWriter().write(
                    "\"" + role + "\""
            );

            if(cpt < roles.size()){
                response.getWriter().write(
                        ","
                );
            }else{
                response.getWriter().write(
                        "]"
                );
            }
        }

        response.getWriter().write(
                "}"
        );

        //ResponseEntity.ok(jwt);
    }
}

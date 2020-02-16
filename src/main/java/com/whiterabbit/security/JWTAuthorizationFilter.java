package com.whiterabbit.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
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
import java.util.List;

public class JWTAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //autoriser requettes cros-domain et ajout token dans header via authorisation en dernier paramètre
        response.addHeader("Access-Control-Allow-Origin", "*");
        response.addHeader("Access-Control-Allow-Headers", "Origin, Accept, X-Request-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, authorization");
        response.addHeader("Access-Control-Allow-Expose-Headers", "Access-Control-Allow-Origin, Access-Control-Allow-Credentials, authorization");
        //autoriser request cors put, delete
        response.addHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH");
        //si requete envoyé avec OPTIONS pas de recherche de token on repond OK car pas encore de token, le navigateur demande juste autorisation cross domain
        if(request.getMethod().equals("OPTION")){
            response.setStatus(HttpServletResponse.SC_OK);
        //pas de recherche tokken non plus car accès page pour s'autentifier pas encore de token
        }else if(request.getRequestURI().equals("/login")){
            filterChain.doFilter(request,response);
            return;
        }
        //sinon recherche du token
         else {

            //recup token JWT passé dans la requette client
            String jwt = request.getHeader(SecurityParams.JWT_HEADER_NAME);
            if (jwt == null || !jwt.startsWith(SecurityParams.HEADER_PREFIX)) {
                //passage au filtre suivant
                filterChain.doFilter(request, response);
                return;
            }

            //vérifier la signature du token (sans le prefix)
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(SecurityParams.SECRET)).build();
            DecodedJWT decodedJWT = jwtVerifier.verify(jwt.substring(SecurityParams.HEADER_PREFIX.length()));

            //recup user et roles dans le token (pas besoin accès base les roles sont dans le token dans notre cas)
            String username = decodedJWT.getSubject();
            List<String> roles = decodedJWT.getClaims().get("roles").asList(String.class);
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            roles.forEach(roleName -> {
                authorities.add(new SimpleGrantedAuthority(roleName));
            });

            //Spring authentifie le user
            UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(user);

            //passer au filtre suivant
            filterChain.doFilter(request, response);
        }
    }
}

package com.whiterabbit.security;

import com.whiterabbit.entities.AppUser;
import com.whiterabbit.services.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    AccountService accountService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("enter in UserDetailsServiceImpl");
        AppUser appUser= accountService.loadUserByUsername(username);

        if(appUser==null) throw new UsernameNotFoundException("user invalid");
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        appUser.getRoles().forEach(role->{
          authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
        });
        //obj User de spring pr verif mdp saisie en l encodant = mdp en base deja encode
        return new User(appUser.getUsername(), appUser.getPassword(), authorities);
    }
}

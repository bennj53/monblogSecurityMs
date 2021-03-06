package com.whiterabbit.controller;

import com.whiterabbit.entities.AppUser;
import com.whiterabbit.services.AccountService;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class UserController {

    @Autowired
    private AccountService accountService;

    @PostMapping("/register")
    public AppUser register(@RequestBody UserForm userForm){
        System.out.println("enter to register controller");
        System.out.println(String.format("USERNAME : %s --- PASSWORD : %s --- CONFIRMED PASSWORD : %s", userForm.getUsername(), userForm.getPassword(), userForm.getConfirmedPassword()));
        return accountService.saveUser(userForm.getUsername(),userForm.getPassword(),userForm.getConfirmedPassword());
    }

   @PostMapping("/login")
    public void login(@RequestBody UserForm userForm){
        System.out.println("enter to login controller.......................................");

        //return accountService.loadUserByUsername(userForm.getUsername());
    }
}

@Data
class UserForm{
    private String username;
    private String password;
    private String confirmedPassword;

}
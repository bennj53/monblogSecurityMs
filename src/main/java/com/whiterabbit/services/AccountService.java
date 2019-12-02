package com.whiterabbit.services;

import com.whiterabbit.entities.AppRole;
import com.whiterabbit.entities.AppUser;

public interface AccountService {
    AppUser saveUser(String username, String password, String confirmedPassword);
    AppRole save(AppRole role);
    AppUser loadUserByUsername(String username);
    void addRoleToUser(String username, String roleName);
}

package com.jb.security.db_auth;

import java.util.Optional;

public interface ApplicationUserDAO {
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}

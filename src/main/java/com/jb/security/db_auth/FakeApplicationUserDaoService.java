package com.jb.security.db_auth;

import com.google.common.collect.Lists;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.jb.security.security.ApplicationUserRole.ADMIN;
import static com.jb.security.security.ApplicationUserRole.CLIENT;

@RequiredArgsConstructor
@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDAO {
    private final PasswordEncoder passwordEncoder;

    //in memory storage database
    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUser()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUser() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        "zeevmindali",
                        passwordEncoder.encode("12345"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "client",
                        passwordEncoder.encode("12345"),
                        CLIENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
        return applicationUsers;
    }
}

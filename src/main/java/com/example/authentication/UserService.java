package com.example.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {

    private final static String USER_TEST = "user";

    private final LoggedInChecker loggedInChecker;

    @Autowired
    UserService(LoggedInChecker loggedInChecker) {
        this.loggedInChecker = loggedInChecker;
    }

    public User getUserByUsername(String username) {
        // Just a mock interface support only one single root
        // Here you can add DAO to load user from the database
        if (username.equals(USER_TEST)) {
            User user = new User();
            user.setLogin(USER_TEST);
            user.setPassword(NoOpPasswordEncoder.getInstance().encode("password"));

            return user;
        } else {
            return null;
        }
    }

    public List<String> getPermissions(String username) {
        return new ArrayList<>();
    }

    public User getCurrentUser() {
        return loggedInChecker.getLoggedInUser();
    }

    public Boolean isCurrentUserLoggedIn() {
        return loggedInChecker.getLoggedInUser() != null;
    }

}

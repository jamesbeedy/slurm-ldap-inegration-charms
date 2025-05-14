package com.example.keycloak;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.GroupModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.RealmModel;


public class UserCreationEventListenerProvider implements EventListenerProvider {

    private final KeycloakSession session;

    public UserCreationEventListenerProvider(KeycloakSession session) {
        this.session = session;
    }

    // User self-registration
    @Override
    public void onEvent(Event event) {
        if (event.getType() == EventType.REGISTER) {
            String userId = event.getUserId();
            RealmModel realm = session.getContext().getRealm();
            UserModel user = session.users().getUserById(realm, userId);

            if (user != null) {
                applyDefaultUserAttributes(user, realm);
                System.out.println("✅ User registered: " + user.getUsername());
            }
        }
    }

    // Admin-created users (via Admin Console/API)
    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if (event.getOperationType() == OperationType.CREATE &&
            event.getResourceType() == ResourceType.USER) {

            String userId = extractUserId(event.getResourcePath());
            RealmModel realm = session.getContext().getRealm();
            UserModel user = session.users().getUserById(realm, userId);

            if (user != null) {
                applyDefaultUserAttributes(user, realm);
                System.out.println("✅ Admin created user: " + user.getUsername());
            }
        }
    }

    // Helper method must be inside the class!
    private String extractUserId(String path) {
        if (path != null && path.contains("/")) {
            return path.substring(path.lastIndexOf('/') + 1);
        }
        return path;
    }

    private void applyDefaultUserAttributes(UserModel user, RealmModel realm) {
        String username = user.getUsername();

        user.setFirstName(username);
        user.setLastName(username);

        user.setSingleAttribute("uidNumber", "5555");
        user.setSingleAttribute("gidNumber", "5555");
        user.setSingleAttribute("loginShell", "/bin/bash");
        user.setSingleAttribute("homeDirectory", "/home/" + username);

        // 🔗 Add user to "slurm-users" group
        //GroupModel group = realm.getGroupsStream()
        //    .filter(g -> g.getName().equals("slurm-users"))
        //    .findFirst()
        //    .orElse(null);

        //if (group != null) {
       //     user.joinGroup(group);
       //     System.out.println("✅ Added user " + username + " to group 'slurm-users'");
       // } else {
        //    System.err.println("⚠️ Group 'slurm-users' not found in realm!");
       // }

    }

    @Override
    public void close() {}
}


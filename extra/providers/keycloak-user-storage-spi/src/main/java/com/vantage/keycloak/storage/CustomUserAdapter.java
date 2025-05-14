package com.vantage.keycloak.storage;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;
import org.keycloak.representations.idm.UserRepresentation;

public class CustomUserAdapter extends AbstractUserAdapterFederatedStorage {

    private final UserRepresentation external;

    public CustomUserAdapter(KeycloakSession session, RealmModel realm, 
                             ComponentModel model, UserRepresentation external) {
        super(session, realm, model);
        this.external = external;
    }

    @Override
    public String getUsername() {
        return external.getUsername();
    }

    // --- NEW setter override ---
    @Override
    public void setUsername(String username) {
        // Persist username into federated storage
        setSingleAttribute(UserModel.USERNAME, username);
        // Also update the backing representation if needed
        external.setUsername(username);
    }

    @Override
    public String getEmail() {
        return external.getEmail();
    }

    @Override
    public boolean isEnabled() {
        return external.isEnabled();
    }

    // override other getters/setters as needed
}


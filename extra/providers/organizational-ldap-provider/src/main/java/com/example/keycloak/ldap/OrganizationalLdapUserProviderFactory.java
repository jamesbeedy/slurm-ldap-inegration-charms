package com.omnivector.keycloak.storage;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.storage.UserStorageProviderFactory;

public class CustomUserStorageProviderFactory 
        implements UserStorageProviderFactory<CustomUserStorageProvider> {

    public static final String PROVIDER_ID = "custom-user-storage";

    @Override
    public CustomUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        return new CustomUserStorageProvider(session, model);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        // optional: read global config
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // optional: after all providers are registered
    }

    @Override
    public void close() {
        // cleanup if needed
    }
}

package com.vantage.keycloak.storage;

import java.util.List;
import java.util.ArrayList;

import org.keycloak.Config.Scope;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;

// Static imports for property types
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.PASSWORD;

/**
 * Factory for the CustomUserStorageProvider.
 */
public class CustomUserStorageProviderFactory
        implements UserStorageProviderFactory<CustomUserStorageProvider> {

    public static final String PROVIDER_ID         = "custom-user-storage";
    public static final String PROP_LDAP_HOST      = "ldapHost";
    public static final String PROP_LDAP_PORT      = "ldapPort";
    public static final String PROP_LDAP_BIND_DN   = "bindDn";
    public static final String PROP_LDAP_BIND_CRED = "bindCredential";
    public static final String PROP_SEARCH_BASE    = "searchBase";

    @Override
    public CustomUserStorageProvider create(KeycloakSession session,
                                            ComponentModel model) {
        return new CustomUserStorageProvider(session, model);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Scope config) {
        // Called once at server startup (keycloak_server.json scope)
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
        // Called after all factories have been initialized
    }

    @Override
    public void close() {
        // Cleanup when server shuts down
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> props = new ArrayList<>();

        props.add(new ProviderConfigProperty(
            PROP_LDAP_HOST,
            "LDAP Host",
            "Hostname or IP address of your LDAP server",
            STRING_TYPE,
            "localhost"
        ));

        props.add(new ProviderConfigProperty(
            PROP_LDAP_PORT,
            "LDAP Port",
            "Port number for your LDAP server",
            STRING_TYPE,
            "389"
        ));

        props.add(new ProviderConfigProperty(
            PROP_LDAP_BIND_DN,
            "Bind DN",
            "Distinguished Name to bind as when performing searches",
            STRING_TYPE,
            "cn=admin,dc=example,dc=com"
        ));

        props.add(new ProviderConfigProperty(
            PROP_LDAP_BIND_CRED,
            "Bind Credential",
            "Password for the Bind DN",
            PASSWORD,
            null
        ));

        props.add(new ProviderConfigProperty(
            PROP_SEARCH_BASE,
            "Search Base DN",
            "Base DN under which to search for users",
            STRING_TYPE,
            "dc=example,dc=com"
        ));

        return props;
    }
}


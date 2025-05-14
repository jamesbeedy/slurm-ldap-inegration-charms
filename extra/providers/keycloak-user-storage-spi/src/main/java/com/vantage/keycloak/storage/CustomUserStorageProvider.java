package com.vantage.keycloak.storage;

import static com.vantage.keycloak.storage.CustomUserStorageProviderFactory.PROP_LDAP_HOST;
import static com.vantage.keycloak.storage.CustomUserStorageProviderFactory.PROP_LDAP_PORT;
import static com.vantage.keycloak.storage.CustomUserStorageProviderFactory.PROP_LDAP_BIND_DN;
import static com.vantage.keycloak.storage.CustomUserStorageProviderFactory.PROP_LDAP_BIND_CRED;
import static com.vantage.keycloak.storage.CustomUserStorageProviderFactory.PROP_SEARCH_BASE;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.StorageId;
import org.keycloak.representations.idm.UserRepresentation;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;

/**
 * LDAP-backed UserStorageProvider implementation.
 */
public class CustomUserStorageProvider implements UserStorageProvider, UserLookupProvider {

    private final KeycloakSession session;
    private final ComponentModel model;
    private final String searchBase;

    public CustomUserStorageProvider(KeycloakSession session, ComponentModel model) {
        this.session    = session;
        this.model      = model;
        this.searchBase = model.get(PROP_SEARCH_BASE);
    }

    private LDAPConnection getLdapConnection() throws LDAPException {
        String host = model.get(PROP_LDAP_HOST);
        int port    = Integer.parseInt(model.get(PROP_LDAP_PORT));
        String dn   = model.get(PROP_LDAP_BIND_DN);
        String pw   = model.get(PROP_LDAP_BIND_CRED);
        return new LDAPConnection(host, port, dn, pw);
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        try (LDAPConnection conn = getLdapConnection()) {
            String filter = "(uid=" + username + ")";
            SearchResult result = conn.search(searchBase, SearchScope.SUB, filter);
            if (result.getEntryCount() == 0) {
                return null;
            }
            SearchResultEntry entry = result.getSearchEntries().get(0);
            UserRepresentation rep = toRepresentation(entry);
            return new CustomUserAdapter(session, realm, model, rep);
        } catch (LDAPException e) {
            // you may want to log here
            return null;
        }
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        try (LDAPConnection conn = getLdapConnection()) {
            String filter = "(mail=" + email + ")";
            SearchResult result = conn.search(searchBase, SearchScope.SUB, filter);
            if (result.getEntryCount() == 0) {
                return null;
            }
            SearchResultEntry entry = result.getSearchEntries().get(0);
            UserRepresentation rep = toRepresentation(entry);
            return new CustomUserAdapter(session, realm, model, rep);
        } catch (LDAPException e) {
            return null;
        }
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        // Keycloak stores IDs as storageProviderId:externalId
        String externalId = StorageId.externalId(id);
        try (LDAPConnection conn = getLdapConnection()) {
            SearchResultEntry entry = conn.getEntry(externalId);
            if (entry == null) {
                return null;
            }
            UserRepresentation rep = toRepresentation(entry);
            return new CustomUserAdapter(session, realm, model, rep);
        } catch (LDAPException e) {
            return null;
        }
    }

    @Override
    public void close() {
        // No-op. Connection is closed per-operation.
    }

    /**
     * Map LDAP entry to Keycloak UserRepresentation.
     */
    private UserRepresentation toRepresentation(SearchResultEntry entry) {
        UserRepresentation rep = new UserRepresentation();
        rep.setUsername(entry.getAttributeValue("uid"));
        rep.setEmail(entry.getAttributeValue("mail"));
        rep.setEnabled(true);
        // you can map other attributes here, e.g. firstName, lastName:
        // rep.setFirstName(entry.getAttributeValue("givenName"));
        // rep.setLastName(entry.getAttributeValue("sn"));
        return rep;
    }
}


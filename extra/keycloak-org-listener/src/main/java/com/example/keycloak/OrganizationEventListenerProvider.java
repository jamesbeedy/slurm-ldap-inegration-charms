package com.example.keycloak;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.common.util.MultivaluedHashMap;


import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.Map;

public class OrganizationEventListenerProvider implements EventListenerProvider {

    private final KeycloakSession session;

    public OrganizationEventListenerProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        // Not needed here
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if (event.getOperationType() == OperationType.CREATE &&
            event.getResourceType() == ResourceType.ORGANIZATION) {

            RealmModel realm = session.getContext().getRealm();

            String orgName = extractOrgName(event.getResourcePath());
	    String orgId = extractOrgId(event.getResourcePath());


            if (orgName != null) {
                try {
                    createLdapOrganizationalUnit(orgName);

                    System.out.println("OU created for organization: " + orgName);

		    createLdapFederationProvider(realm, orgId);

                } catch (NamingException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private String extractOrgName(String resourcePath) {
        // Example resourcePath: "organizations/org-id" or similar
        if (resourcePath != null && resourcePath.contains("/")) {
            return resourcePath.substring(resourcePath.lastIndexOf("/") + 1);
        }
        return resourcePath;
    }

    private String extractOrgId(String path) {
        return path.substring(path.lastIndexOf("/") + 1);
    }

    private void createLdapFederationProvider(RealmModel realm, String orgId) {
        ComponentModel ldapComponent = new ComponentModel();
        ldapComponent.setName("ldap-" + orgId);
        ldapComponent.setParentId(realm.getId());
        ldapComponent.setProviderId("ldap");
	ldapComponent.setProviderType("org.keycloak.storage.UserStorageProvider");
        ldapComponent.setSubType(null);
        ldapComponent.setConfig(new MultivaluedHashMap<>());
    
        // Config - adapt as needed for your LDAP layout
        ldapComponent.getConfig().putSingle("priority", "1");
        ldapComponent.getConfig().putSingle("enabled", "true");
        ldapComponent.getConfig().putSingle("editMode", "WRITABLE");
        ldapComponent.getConfig().putSingle("vendor", "other");
        ldapComponent.getConfig().putSingle("usernameLDAPAttribute", "uid");
        ldapComponent.getConfig().putSingle("rdnLDAPAttribute", "uid");
        ldapComponent.getConfig().putSingle("uuidLDAPAttribute", "entryUUID");
        ldapComponent.getConfig().putSingle("userObjectClasses", "top,inetOrgPerson,posixAccount,ldapPublicKey");
        ldapComponent.getConfig().putSingle("connectionUrl", "ldaps://" + System.getenv("LDAP_HOST"));
        ldapComponent.getConfig().putSingle("usersDn", "ou=People,ou=" + orgId + ",ou=organizations,dc=vantage");
        ldapComponent.getConfig().putSingle("bindDn", "cn=admin,dc=vantage");
        ldapComponent.getConfig().putSingle("bindCredential", System.getenv("LDAP_ADMIN_PASSWORD"));

        // Save to realm
        ComponentModel createdProvider = realm.addComponentModel(ldapComponent);
        String parentId = createdProvider.getId();
    
        addMapper(realm, parentId, "sshPublicKey", "user-attribute-ldap-mapper", mapOf(
            "ldap.attribute", "sshPublicKey",
            "attribute.force.default", "false",
            "is.mandatory.in.ldap", "false",
            "is.binary.attribute", "false",
            "read.only", "false",
            "user.model.attribute", "sshPublicKey"
        ));
    
        addMapper(realm, parentId, "loginShell", "user-attribute-ldap-mapper", mapOf(
            "ldap.attribute", "loginShell",
            "attribute.default.value", "/bin/bash",
            "attribute.force.default", "true",
            "is.mandatory.in.ldap", "false",
            "is.binary.attribute", "false",
            "read.only", "false",
            "user.model.attribute", "loginShell"
        ));
    
        addMapper(realm, parentId, "gidNumber", "user-attribute-ldap-mapper", mapOf(
            "ldap.attribute", "gidNumber",
            "attribute.force.default", "false",
            "is.mandatory.in.ldap", "true",
            "is.binary.attribute", "false",
            "read.only", "false",
            "user.model.attribute", "gidNumber"
        ));
    
        addMapper(realm, parentId, "uidNumber", "user-attribute-ldap-mapper", mapOf(
            "ldap.attribute", "uidNumber",
            "attribute.force.default", "false",
            "is.mandatory.in.ldap", "true",
            "is.binary.attribute", "false",
            "read.only", "false",
            "user.model.attribute", "uidNumber"
        ));
    
        addMapper(realm, parentId, "homeDirectory", "user-attribute-ldap-mapper", mapOf(
            "ldap.attribute", "homeDirectory",
            "attribute.force.default", "false",
            "is.mandatory.in.ldap", "true",
            "is.binary.attribute", "false",
            "read.only", "false",
            "user.model.attribute", "homeDirectory"
        ));
    
        addMapper(realm, parentId, "slurm-users", "group-ldap-mapper", mapOf(
            "mode", "LDAP_ONLY",
            "membership.attribute.type", "DN",
            "user.roles.retrieve.strategy", "LOAD_GROUPS_BY_MEMBER_ATTRIBUTE",
            "group.name.ldap.attribute", "cn",
            "membership.ldap.attribute", "member",
            "membership.user.ldap.attribute", "uid",
            "preserve.group.inheritance", "true",
            "ignore.missing.groups", "false",
            "memberof.ldap.attribute", "memberOf",
            "group.object.classes", "groupOfNames",
            "groups.dn", "ou=Groups,ou=" + orgId + ",ou=organizations,dc=vantage",
            "groups.path", "/",
            "drop.non.existing.groups.during.sync", "false"
        ));

    
        System.out.println("Federation provider for org " + orgId + " created.");
    }

    private void createLdapOrganizationalUnit(String orgName) throws NamingException {

        String ldapUrl = "ldaps://" + System.getenv("LDAP_HOST");
        String bindPassword = System.getenv("LDAP_ADMIN_PASSWORD");

        String bindDn = "cn=admin,dc=vantage";
        String baseDn = "ou=" + orgName + ",ou=organizations,dc=vantage";

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, bindDn);
        env.put(Context.SECURITY_CREDENTIALS, bindPassword);

        DirContext ctx = new InitialDirContext(env);

        Attributes attrs = new BasicAttributes(true);
        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("organizationalUnit");
        attrs.put(oc);
        attrs.put("ou", orgName);
        ctx.createSubcontext(baseDn, attrs);

        Attributes attrs1 = new BasicAttributes(true);
        Attribute oc1 = new BasicAttribute("objectClass");
        oc1.add("top");
        oc1.add("organizationalUnit");
        attrs1.put(oc1);
        attrs1.put("ou", "People");
        ctx.createSubcontext("ou=People," + baseDn, attrs1);

        Attributes attrs2 = new BasicAttributes(true);
        Attribute oc2 = new BasicAttribute("objectClass");
        oc2.add("top");
        oc2.add("organizationalUnit");
        attrs2.put(oc2);
        attrs2.put("ou", "Groups");
        ctx.createSubcontext("ou=Groups," + baseDn, attrs2);

        Attributes attrs3 = new BasicAttributes(true);
        Attribute oc3 = new BasicAttribute("objectClass");
        oc3.add("top");
        oc3.add("organizationalUnit");
        attrs3.put(oc3);
        attrs3.put("ou", "ServiceAccounts");
        ctx.createSubcontext("ou=ServiceAccounts," + baseDn, attrs3);

        ctx.close();
    }

    private void addMapper(RealmModel realm, String parentId, String name, String providerId, Map<String, String> config) {
        ComponentModel mapper = new ComponentModel();
        mapper.setName(name);
        mapper.setProviderId(providerId);
        mapper.setParentId(parentId);
        mapper.setProviderType("org.keycloak.storage.ldap.mappers.LDAPStorageMapper");
    
        MultivaluedHashMap<String, String> map = new MultivaluedHashMap<>();
        if (config != null) {
            config.forEach((k, v) -> map.putSingle(k, v));
        }
        mapper.setConfig(map);
    
        realm.addComponentModel(mapper);
    }


    private static Map<String, String> mapOf(String... keyValues) {
        if (keyValues.length % 2 != 0) {
            throw new IllegalArgumentException("mapOf requires an even number of arguments (key-value pairs)");
        }

        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            map.put(keyValues[i], keyValues[i + 1]);
        }
        return map;
    }


    @Override
    public void close() {
        // Clean up
    }
}


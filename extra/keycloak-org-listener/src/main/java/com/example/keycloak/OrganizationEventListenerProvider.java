package com.example.keycloak;

import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.models.KeycloakSession;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.Hashtable;

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

            String orgName = extractOrgName(event.getResourcePath());
            if (orgName != null) {
                try {
                    createLdapOrganizationalUnit(orgName);
                    System.out.println("OU created for organization: " + orgName);
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

    private void createLdapOrganizationalUnit(String orgName) throws NamingException {
        String ldapUrl = "ldaps://192.168.7.67";
        String bindDn = "cn=admin,dc=vantage";
        String bindPassword = "XvXOQ7nCqrbuamdipT8bbR9mx1OtDeLpTLcycFpN3bY";
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

    @Override
    public void close() {
        // Clean up
    }
}


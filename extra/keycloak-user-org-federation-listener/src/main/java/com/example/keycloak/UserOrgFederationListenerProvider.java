// FederationLink via Organization Membership Listener
package com.example.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.storage.user.UserLookupProvider;
import org.jboss.logging.Logger;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class UserOrgFederationListenerProvider implements EventListenerProvider {

    private static final Logger logger = Logger.getLogger(UserOrgFederationListenerProvider.class);
    private static final Pattern EXPECTED_PATH_PATTERN = Pattern.compile("^organizations/([^/]+)/members$", Pattern.CASE_INSENSITIVE);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final KeycloakSession session;

    public UserOrgFederationListenerProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {}

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if (event.getOperationType() != OperationType.CREATE || 
            !"ORGANIZATION_MEMBERSHIP".equals(event.getResourceTypeAsString())) {
            return;
        }

        String operation = event.getOperationType().toString();
        String resourceType = event.getResourceTypeAsString();
        String path = event.getResourcePath();

        logger.infof("\uD83E\uDDE9 AdminEvent Received — Operation: %s, ResourceType: %s, Path: %s", operation, resourceType, path);

        boolean hasResourcePath = path != null;
        boolean pathMatches = hasResourcePath && EXPECTED_PATH_PATTERN.matcher(path).matches();

        logger.infof("\uD83D\uDD0D hasResourcePath: %s, pathMatches: %s", hasResourcePath, pathMatches);

        if (!pathMatches && hasResourcePath) {
            logger.warnf("\u26A0\uFE0F Condition not met: ResourcePath '%s' does not match expected format '%s'", path, EXPECTED_PATH_PATTERN.pattern());
            String[] parts = path.split("/");
            logger.infof("\uD83D\uDD0E Path parts (%d): %s", parts.length, java.util.Arrays.toString(parts));
        }

        if (!pathMatches) {
            logger.info("\u2139\uFE0F Skipping event — conditions not met");
            return;
        }

        try {
            JsonNode representation = event.getRepresentation() != null
                ? objectMapper.readTree(event.getRepresentation())
                : null;

            if (representation != null) {
                logger.infof("\uD83D\uDCE6 Full representation: %s", representation.toPrettyString());
            } else {
                logger.warn("\u26A0\uFE0F No representation available in event");
            }

            Matcher matcher = EXPECTED_PATH_PATTERN.matcher(path);
            String orgId = null;
            if (matcher.matches()) {
                orgId = matcher.group(1);
            }

            String userId = null;

            if (orgId != null) {
                OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
                if (orgProvider != null) {
                    OrganizationModel org = (OrganizationModel) orgProvider.getById(orgId);
                    if (org != null) {
                        HashMap<String, String> filters = new HashMap<>();
                        Stream<UserModel> members = orgProvider.getMembersStream(org, filters, null, null, null);
                        List<UserModel> sorted = members
                            .sorted(Comparator.comparing(UserModel::getCreatedTimestamp).reversed())
                            .collect(Collectors.toList());

                        UserModel latest = sorted.isEmpty() ? null : sorted.get(0);
                        if (latest != null) {
                            userId = latest.getId();
                            logger.infof("\uD83D\uDD0E Inferred userId from latest member: %s", latest.getUsername());
                        }
                    } else {
                        logger.warnf("\u26A0\uFE0F organization with ID '%s' not found", orgId);
                    }
                } else {
                    logger.warn("\u26A0\uFE0F OrganizationProvider not available");
                }
            }

            logger.infof("\uD83D\uDD0E Final orgId: %s, userId: %s", orgId, userId);

            if (userId == null || orgId == null) {
                logger.warnf("\u26A0\uFE0F Skipping — userId or orgId missing. userId=%s, orgId=%s", userId, orgId);
                return;
            }

            addUserToOrgAndSetFederationLink(userId, orgId);

        } catch (Exception e) {
            logger.error("\u274C Error processing AdminEvent", e);
        }
    }

    private void addUserToOrgAndSetFederationLink(String userId, String orgId) {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);

        logger.infof("\uD83D\uDD27 [addUserToOrgAndSetFederationLink] realm: %s, user: %s", realm.getName(), user != null ? user.getUsername() : "null");

        if (user == null) {
            logger.warnf("\u26A0\uFE0F No user found for userId: %s", userId);
            return;
        }

        OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
        logger.infof("\uD83D\uDD27 orgProvider available: %s", orgProvider != null);

        if (orgProvider == null) {
            logger.warn("\u26A0\uFE0F OrganizationProvider not available");
            return;
        }

        OrganizationModel org = (OrganizationModel) orgProvider.getById(orgId);
        logger.infof("\uD83D\uDD27 Organization resolved: %s", org != null ? org.toString() : "null");

        if (org == null) {
            logger.warnf("\u26A0\uFE0F organization with ID '%s' not found", orgId);
            return;
        }

        try {
            orgProvider.addMember(org, user);
            logger.infof("\uD83D\uDC65 user '%s' added to organization '%s'", user.getUsername(), orgId);
        } catch (Exception e) {
            logger.errorf(e, "\u274C Failed to add user '%s' to organization '%s'", user.getUsername(), orgId);
            return;
        }

        String expectedProviderName = "ldap-" + orgId;
        logger.infof("\uD83D\uDD27 Looking for federation provider named '%s'", expectedProviderName);

        String federationProviderId = realm.getComponentsStream()
            .filter(component ->
                component.getProviderType().equals("org.keycloak.storage.UserStorageProvider") &&
                component.getName().equals(expectedProviderName))
            .map(ComponentModel::getId)
            .findFirst()
            .orElse(null);

        if (federationProviderId != null) {
            UserProvider userProvider = session.getProvider(UserProvider.class);
            UserModel existing = userProvider.getUserByUsername(realm, user.getUsername());
            if (existing != null && existing.getFederationLink() == null) {
                user.setFederationLink(federationProviderId);
                logger.infof("\uD83D\uDD17 federationLink set for user '%s' to '%s'", user.getUsername(), federationProviderId);
            } else {
                logger.warnf("\u26A0\uFE0F federationLink not set — user '%s' already linked or not found in storage", user.getUsername());
            }
        } else {
            logger.warnf("\u26A0\uFE0F federation provider '%s' not found", expectedProviderName);
        }
    }

    @Override
    public void close() {}
}


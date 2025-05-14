# Keycloak Organizational LDAP User Storage Provider

This Keycloak User Storage Provider allows you to sync new users to specific LDAP Organizational Units (OUs) based on their `organization` user attribute in Keycloak.

## Prerequisites

* Java Development Kit (JDK)
* Apache Maven or Gradle
* A running Keycloak server

## Building the Provider

**Using Maven:**

```bash
mvn clean package
```

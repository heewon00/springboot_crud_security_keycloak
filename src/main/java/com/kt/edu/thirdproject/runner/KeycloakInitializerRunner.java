package com.kt.edu.thirdproject.runner;

import com.kt.edu.thirdproject.security.WebSecurityConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.*;

@Slf4j
@RequiredArgsConstructor
@Component
// KeycloakInitializerRunner 는 realm 생성하고 삭제 반복. 주석 처리하고 수정 생성
public class KeycloakInitializerRunner implements CommandLineRunner {

    private final Keycloak keycloakAdmin;

    @Value("${app.keycloak.server}")
    private String KEYCLOAK_SERVER_URL;

    //@Override
    public void run(String... args) {
        log.info("Initializing '{}' realm in Keycloak ...", EMYPLOEE_SERVICE_REALM_NAME);

        Optional<RealmRepresentation> representationOptional = keycloakAdmin.realms()
                .findAll()
                .stream()
                .filter(r -> r.getRealm().equals(EMYPLOEE_SERVICE_REALM_NAME))
                .findAny();
        if (representationOptional.isPresent()) {
            log.info("Removing already pre-configured '{}' realm", EMYPLOEE_SERVICE_REALM_NAME);
            keycloakAdmin.realm(EMYPLOEE_SERVICE_REALM_NAME).remove();
        }

        // Realm
        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setRealm(EMYPLOEE_SERVICE_REALM_NAME);
        realmRepresentation.setEnabled(true);
        realmRepresentation.setRegistrationAllowed(true);

        // Client
        ClientRepresentation clientRepresentation = new ClientRepresentation();
        clientRepresentation.setClientId(EDU_APP_CLIENT_ID);
        clientRepresentation.setDirectAccessGrantsEnabled(true);
        clientRepresentation.setPublicClient(true);
        clientRepresentation.setRedirectUris(List.of(EDU_APP_REDIRECT_URL));
        clientRepresentation.setDefaultRoles(new String[]{WebSecurityConfig.EDU_USER});
        realmRepresentation.setClients(List.of(clientRepresentation));

        // Users
        List<UserRepresentation> userRepresentations = EDU_USER_LIST.stream()
                .map(userPass -> {
                    // User Credentials
                    CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
                    credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
                    credentialRepresentation.setValue(userPass.password());

                    // User
                    UserRepresentation userRepresentation = new UserRepresentation();
                    userRepresentation.setUsername(userPass.username());
                    userRepresentation.setEnabled(true);
                    userRepresentation.setCredentials(List.of(credentialRepresentation));
                    userRepresentation.setClientRoles(getClientRoles(userPass));

                    return userRepresentation;
                })
                .toList();
        realmRepresentation.setUsers(userRepresentations);

        // Create Realm
        keycloakAdmin.realms().create(realmRepresentation);

        // Testing
        UserPass admin = EDU_USER_LIST.get(0);
        log.info("Testing getting token for '{}' ...", admin.username());

        log.info("admin password '{}' ...", admin.password());


        Keycloak keycloakMovieApp = KeycloakBuilder.builder().serverUrl(KEYCLOAK_SERVER_URL)
                .realm(EMYPLOEE_SERVICE_REALM_NAME).username(admin.username()).password(admin.password())
                //.realm("master").username(admin.username()).password(admin.password())
                .grantType(OAuth2Constants.PASSWORD)
                //.clientSecret("qhhAYK7k7898gANjeGnpad1Dy7Gu03VR")
                .clientId(EDU_APP_CLIENT_ID).build();
               // .clientId("admin-api").build();

        log.info("'{}' token: {}", admin.username(), keycloakMovieApp.tokenManager().grantToken().getToken());
        log.info("'{}' initialization completed successfully!", EMYPLOEE_SERVICE_REALM_NAME);
    }

    private Map<String, List<String>> getClientRoles(UserPass userPass) {
        List<String> roles = new ArrayList<>();
        roles.add(WebSecurityConfig.EDU_USER);
        if ("admin".equals(userPass.username())) {
            roles.add(WebSecurityConfig.EDU_MANAGER);
        }
        return Map.of(EDU_APP_CLIENT_ID, roles);
    }

    private static final String EMYPLOEE_SERVICE_REALM_NAME = "employee-services";
    private static final String EDU_APP_CLIENT_ID = "edu-app";
    private static final String EDU_APP_REDIRECT_URL = "http://localhost:3000/*";
    //private static final String EDU_APP_REDIRECT_URL = "*";
    private static final List<UserPass> EDU_USER_LIST = Arrays.asList(
            new UserPass("admin", "admin"),
            new UserPass("edu", "edu"),
            new UserPass("user", "user"));

    private record UserPass(String username, String password) {
    }
}
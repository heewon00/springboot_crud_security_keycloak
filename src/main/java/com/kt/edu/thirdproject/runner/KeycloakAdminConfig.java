package com.kt.edu.thirdproject.runner;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakAdminConfig {

    @Value("${app.keycloak.server}")
    private String KEYCLOAK_SERVER_URL;

    @Bean
    public Keycloak keycloakAdmin() {

        return KeycloakBuilder.builder()
                .serverUrl(KEYCLOAK_SERVER_URL)
                .realm("master")
                .username("admin")
                .password("New1234!")
                .clientId("admin-cli")
                //.clientId("admin-api")
                .build();
    }
}

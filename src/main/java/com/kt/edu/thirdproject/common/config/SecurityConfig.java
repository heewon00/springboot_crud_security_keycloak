//package com.kt.edu.thirdproject.common.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
//import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
//import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//
//import java.util.Collections;
//
//import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    @Autowired
//    private UserDetailsService jwtUserDetailsService;
//
//    @Autowired
//    private JwtRequestFilter jwtRequestFilter;
//
//    //@Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        // configure AuthenticationManager so that it knows from where to load
//        // user for matching credentials
//        // Use BCryptPasswordEncoder
//        auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        //return new BCryptPasswordEncoder();
//        return new Sha256PasswordEncoder(); // default 대신 SHA256 Encoder 사용함
//    }
//
//    // ️ CORS 설정
//    CorsConfigurationSource corsConfigurationSource() {
//        return request -> {
//            CorsConfiguration config = new CorsConfiguration();
//            config.setAllowedHeaders(Collections.singletonList("*"));
//            config.setAllowedMethods(Collections.singletonList("*"));
//            //config.setAllowedMethods(Collections.singletonList("GET"));
//            //config.setAllowedOriginPatterns(Collections.singletonList("http://localhost:3000")); //  허용할 origin
//            config.setAllowedOriginPatterns(Collections.singletonList("*")); //  허용할 origin
//            config.setAllowCredentials(true);
//            return config;
//        };
//    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .cors(corsConfigurer -> corsConfigurer.configurationSource(corsConfigurationSource()))
//                .csrf(AbstractHttpConfigurer::disable)
//                .formLogin(Customizer.withDefaults());
//        http
//                .authorizeHttpRequests(
//                        authorize -> authorize
//                                .requestMatchers(
//                                        "/",
//                                        "/actuator/**",
//                                        "/v3/api-docs/**",
//                                        "/swagger-ui.html",
//                                        "/swagger-ui/**",
////                                        "/api/login",
//                                        "/login",
//                                        "/h2-console/*"
//                                        ).permitAll()
//                                .anyRequest().authenticated()
//                                // make sure we use stateless session; session won't be used to
//                                // store user's state.
//                                //.exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED)).and().sessionManagement()
//                                //.exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint).and().sessionManagement()
//                                //.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                )
//                .headers(
//                headersConfigurer ->
//                        headersConfigurer
//                                .frameOptions( // multi login 시 IFRAME 사용 가능하도록
//                                        HeadersConfigurer.FrameOptionsConfig::sameOrigin
//                                )
//        );
//
//
//        // Add a filter to validate the tokens with every request
//        http.sessionManagement(manager -> manager.sessionCreationPolicy(STATELESS))
//                .authenticationProvider(authenticationProvider()).addFilterBefore(
//                        jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
//
//        return http.build();
//    }
//
//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        // 정적 리소스 spring security 대상에서 제외
//        return (web) ->
//                web
//                        .ignoring()
//                        .requestMatchers(
//                                PathRequest.toStaticResources().atCommonLocations()
//                        );
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
//            throws Exception {
//        return config.getAuthenticationManager();
//    }
//
//    @Bean
//    public AuthenticationProvider authenticationProvider() {
//        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
//        authProvider.setUserDetailsService(jwtUserDetailsService);
//        authProvider.setPasswordEncoder(passwordEncoder());
//        return authProvider;
//    }
//}

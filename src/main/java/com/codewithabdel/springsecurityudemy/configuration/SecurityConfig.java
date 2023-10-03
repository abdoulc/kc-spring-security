package com.codewithabdel.springsecurityudemy.configuration;

import com.codewithabdel.springsecurityudemy.filter.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;
import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableMethodSecurity()
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        CsrfTokenRequestAttributeHandler requestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        requestAttributeHandler.setCsrfRequestAttributeName("_csrf");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

        http
           .authorizeHttpRequests((requests) -> {
                    requests
                            //.anyRequest().denyAll();
                            /*.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                            .requestMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT","VIEWBALANCE")
                            .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                            .requestMatchers("/myCards").hasAuthority("VIEWCARDS")*/
                            .requestMatchers("/myAccount").hasRole("USER")
                            .requestMatchers("/myBalance").hasAnyRole("USER","ADMIN")
                            .requestMatchers("/myLoans").authenticated()
                            .requestMatchers("/myCards").hasRole("USER")
                            .requestMatchers( "/user").authenticated()
                            .requestMatchers("/notices", "/contact", "/register").permitAll();

           })   //FOR JESSIONID
                /*.securityContext(s->s.requireExplicitSave(false))
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))*/
                //DO NOT genrate jsessionid
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
             .cors(corsCustomizer -> corsCustomizer.configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                config.setAllowedMethods(Collections.singletonList("*"));
                config.setAllowCredentials(true);
                config.setAllowedHeaders(Collections.singletonList("*"));
                //inform browser to accept this header, expose an header from backend to different Ui app hosted
                //in another origin, cause it's custom Header
                config.setExposedHeaders(Arrays.asList("Authorization"));
                config.setMaxAge(3600L);
                return config;
        })).csrf(csrf->csrf
                        .csrfTokenRequestHandler(requestAttributeHandler)
                        .ignoringRequestMatchers("/contact", "/register")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                /*.addFilterBefore(new RequestValidationFilter(), BasicAuthenticationFilter.class)

                .addFilterAfter(new LoggingFilter(),BasicAuthenticationFilter.class)
                .addFilterAfter(new JwtTokenGeneratorFIlter(),BasicAuthenticationFilter.class)
                .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)*/
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .oauth2ResourceServer(r->r.jwt(j->j.jwtAuthenticationConverter(jwtAuthenticationConverter)));


        /*http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());*/
        return (SecurityFilterChain)http.build();
    }

    /*@Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setMaxAge(260L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }*/



    /*@Bean
    public UserDetailsService userDetailsService(DataSource dataSource){
        return new JdbcUserDetailsManager(dataSource);
    }*/

    /*@Bean
    public InMemoryUserDetailsManager userDetailsService(){
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("admin")
                .authorities("admin")
                .build();

        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .authorities("user")
                .build();
        return new InMemoryUserDetailsManager(admin, user);
        method2
        UserDetails admin = User
                .withUsername("admin")
                .password("admin")
                .authorities("admin")
                .build();

        UserDetails user = User
                .withUsername("user")
                .password("user")
                .authorities("user")
                .build();
        return new InMemoryUserDetailsManager(admin, user);
    }*/

    /*@Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }*/

}

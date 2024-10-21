package fpt.capstone.iApiGateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.introspection.NimbusReactiveOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Autowired
    private ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(auth -> auth.anyExchange().authenticated())
                .oauth2Login(withDefaults())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .opaqueToken(opaqueToken -> opaqueToken
                                .introspector(reactiveOpaqueTokenIntrospector())
                        )
                        .authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors
                        .configurationSource(request -> {
                            org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();
                            config.addAllowedOrigin("http://localhost:3000"); // Allow the specific origin
                            config.addAllowedOrigin("http://194.233.65.193");
                            config.addAllowedOrigin("http://62.72.45.142:81");
                            config.addAllowedOrigin("https://salesinovate.netlify.app");
                            config.addAllowedMethod("*"); // Allow all methods
                            config.addAllowedHeader("*"); // Allow all headers
                            config.setAllowCredentials(true); // Allow credentials
                            return config;
                        })
                );

        return http.build();
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    @Bean
    public ReactiveOpaqueTokenIntrospector reactiveOpaqueTokenIntrospector() {
        return new NimbusReactiveOpaqueTokenIntrospector(
                "http://194.233.65.193:8080/realms/master/protocol/openid-connect/token/introspect",
                "sales-innovate",
                "kZnyxMsIEYLxqKjM9RkJ4xNSlK5c2SCU"
        );
    }
}



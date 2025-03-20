package dev.xdbe.booking.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth
                // Step 3: add authorization
                .requestMatchers("/dashboard").hasRole("ADMIN")
                .anyRequest().permitAll()
            )
            // Step 3: Add login form
            .formLogin(withDefaults())
            .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/*"))
            .headers(headers -> headers.frameOptions().disable())
            .build();
    }

    // Step 3: add InMemoryUserDetailsManager
    @Bean
    public UserDetailsService users() {
        UserDetails admin = User.withDefaultPasswordEncoder()
            .username("admin")
            .password("admin")
            .roles("ADMIN")
            .build();

        UserDetails user = User.withDefaultPasswordEncoder()
            .username("user")
            .password("user")
            .roles("USER")
            .build();

        return new InMemoryUserDetailsManager(admin, user);
    }
}

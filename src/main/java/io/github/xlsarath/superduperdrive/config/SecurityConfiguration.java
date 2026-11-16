package io.github.xlsarath.superduperdrive.config;

import io.github.xlsarath.superduperdrive.security.ClientRateLimiter;
import io.github.xlsarath.superduperdrive.security.DriveUserDetailsService;
import io.github.xlsarath.superduperdrive.security.KeyUnlockingSuccessHandler;
import io.github.xlsarath.superduperdrive.security.LoginRateLimitFilter;
import io.github.xlsarath.superduperdrive.security.UserMdcFilter;
import io.github.xlsarath.superduperdrive.service.account.AccountService;
import io.github.xlsarath.superduperdrive.service.item.CryptoMigrationService;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter;

/** Spring Security 6 configuration (lambda DSL, no {@code WebSecurityConfigurerAdapter}). */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfiguration {

    /**
     * Strict CSP: everything is served from this origin (Bootstrap via WebJars), no inline
     * scripts or styles, no framing, forms only post back to us.
     */
    static final String CONTENT_SECURITY_POLICY = String.join("; ",
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'");

    private static final String[] PUBLIC_PATHS = {
            "/login", "/signup", "/recover", "/error",
            "/webjars/**", "/css/**", "/js/**", "/img/**", "/favicon.ico", "/actuator/health"
    };

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager,
                                            AccountService accounts, CryptoMigrationService migration,
                                            ClientRateLimiter rateLimiter) throws Exception {
        http
                .authenticationManager(authenticationManager)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(PUBLIC_PATHS).permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(new KeyUnlockingSuccessHandler(accounts, migration))
                        .failureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error"))
                        .permitAll())
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("SDDSESSION"))
                .sessionManagement(session -> session
                        .sessionFixation(fixation -> fixation.changeSessionId())
                        .invalidSessionUrl("/login?expired"))
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY))
                        .frameOptions(frame -> frame.deny())
                        .contentTypeOptions(nosniff -> { })
                        .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .crossOriginOpenerPolicy(coop -> coop.policy(
                                CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN))
                        .permissionsPolicyHeader(permissions -> permissions.policy(
                                "camera=(), microphone=(), geolocation=(), payment=(), usb=()"))
                        // Only emitted on HTTPS requests (for example the pqtls profile).
                        .httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31_536_000).includeSubDomains(true)))
                .addFilterBefore(new LoginRateLimitFilter(rateLimiter), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new UserMdcFilter(), AnonymousAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    AuthenticationManager authenticationManager(DriveUserDetailsService userDetailsService,
                                                PasswordEncoder passwordEncoder,
                                                ApplicationEventPublisher publisher) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsPasswordService(userDetailsService);
        ProviderManager manager = new ProviderManager(provider);
        manager.setAuthenticationEventPublisher(new DefaultAuthenticationEventPublisher(publisher));
        return manager;
    }
}

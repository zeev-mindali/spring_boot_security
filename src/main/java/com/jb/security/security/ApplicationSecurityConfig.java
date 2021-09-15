package com.jb.security.security;

import com.jb.security.JWT.JwtConfig;
import com.jb.security.JWT.JwtTokenVerifier;
import com.jb.security.JWT.JwtUsernameAndPasswordAuthenticationFilter;
import com.jb.security.db_auth.ApplicationUser;
import com.jb.security.db_auth.ApplicationUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity  //configure web security
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    //CTRL+O -> options for extends
    private final JwtConfig jwtConfig;
    private final PasswordEncoder PASSWORD_ENCODER;
    private final ApplicationUserService applicationUserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(),jwtConfig))
                .addFilterAfter(new JwtTokenVerifier(jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
                //make sure that we are using stateless auth.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                //visible to client side script so we can see it on the browser
                //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                //.and()
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*","/media/*","/img/*")
                .permitAll()
                .antMatchers("/test/**").hasRole(ApplicationUserRole.ADMIN.name()) //test only for admin
                //.antMatchers(HttpMethod.DELETE, "/company/**").hasAuthority(ApplicationUserPermission.COMPANY_WRITE.getPermission())
                //.antMatchers(HttpMethod.POST, "/company/**").hasAuthority(ApplicationUserPermission.COMPANY_WRITE.getPermission())
                //.antMatchers(HttpMethod.PUT, "/company/**").hasAuthority(ApplicationUserPermission.COMPANY_WRITE.getPermission())
                //.antMatchers(HttpMethod.GET,"/company/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.SUPPORT.name())
                .anyRequest()
                .authenticated();
                /*
                .and()
                .httpBasic();
                .formLogin()
                    .loginPage("/login").permitAll()
                    .defaultSuccessUrl("/mainpage",true)
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and()
                .rememberMe() //defaults to 2 weeks instead of 30 minutes
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21)) //make bigger expiration date
                    .key("somethingverysecured") //create our own key :)
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID","remember-me")
                .logoutSuccessUrl("/login");
                 */


    }

    /*
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails zeevUser = User.builder()
                .username("zeevmindali")
                .password(PASSWORD_ENCODER.encode("password"))  //it will not work, since password must be encoded
                //.roles(ApplicationUserRole.ADMIN.name())  //Using our new ENUM
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
                .build();

        UserDetails client1= User.builder()
                .username("client")
                .password(PASSWORD_ENCODER.encode("12345"))
                //.roles(ApplicationUserRole.CLIENT.name())
                .authorities(ApplicationUserRole.CLIENT.getGrantedAuthorities())
                .build();

        UserDetails supportUser = User.builder()
                .username("support")
                .password(PASSWORD_ENCODER.encode("12345"))
                //.roles(ApplicationUserRole.SUPPORT.name())
                .authorities(ApplicationUserRole.SUPPORT.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(zeevUser,client1,supportUser);
    }

   */
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(PASSWORD_ENCODER);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }
}

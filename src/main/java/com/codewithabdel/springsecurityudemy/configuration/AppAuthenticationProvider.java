package com.codewithabdel.springsecurityudemy.configuration;

import com.codewithabdel.springsecurityudemy.entity.Customer;
import com.codewithabdel.springsecurityudemy.repository.CustomerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Do Not use when the app is a resources server
 */
/*@Service
public class AppAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String userName = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        List<Customer> customer = customerRepository.findByEmail(userName);
        if(customer.size()==0){
            throw  new BadCredentialsException("No user found with this details");
        }
        if(passwordEncoder.matches(pwd, customer.get(0).getPwd())){
            List<GrantedAuthority> authorities = new ArrayList<>();
            customer.get(0).getAuthorities().forEach(auth -> authorities.add(new SimpleGrantedAuthority(auth.getName())));
            return new UsernamePasswordAuthenticationToken(userName, pwd, authorities);
        }else {
            throw  new BadCredentialsException("Invalid Password !");

        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
*/
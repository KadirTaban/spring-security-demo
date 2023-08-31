package pinecone.springsecuritydemo.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import pinecone.springsecuritydemo.entity.User;
import pinecone.springsecuritydemo.exception.GenericException;
import pinecone.springsecuritydemo.model.enums.Role;
import pinecone.springsecuritydemo.model.request.UserLoginRequest;
import pinecone.springsecuritydemo.model.request.UserRegisterRequest;
import pinecone.springsecuritydemo.model.response.AuthResponse;
import pinecone.springsecuritydemo.repository.UserRepository;
import pinecone.springsecuritydemo.security.JwtService;
import pinecone.springsecuritydemo.security.JwtUserDetails;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public AuthResponse register(@RequestBody UserRegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail()).isEmpty()) {
            throw new GenericException(HttpStatus.BAD_REQUEST, "User has already exists");
        }
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ADMIN)
                .build();

        userRepository.save(user);

        String jwt = jwtService.generateToken(JwtUserDetails.create(user));

        return AuthResponse.builder()
                .token(jwt)
                .build();
    }

    public AuthResponse login(@RequestBody UserLoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        var user= userRepository.findByEmail(request.getEmail())
                .orElseThrow(()-> new UsernameNotFoundException("Kullanıcıya ait email bulunamadı."));

        var jwt = jwtService.generateToken(JwtUserDetails.create(user));

        return AuthResponse.builder()
                .token(jwt)
                .build();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }
}

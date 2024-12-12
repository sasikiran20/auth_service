package com.kluniversity.auth_service.service;

import com.kluniversity.auth_service.dto.LoginDTO;
import com.kluniversity.auth_service.dto.RegisterDTO;
import com.kluniversity.auth_service.dto.VerifyDTO;
import com.kluniversity.auth_service.model.User;
import com.kluniversity.auth_service.repository.UserRepository;
import jakarta.mail.MessagingException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.Random;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final String VERIFICATION_EMAIL_TEMPLATE_PATH = "src/main/resources/templates/verification_email_template.html";

    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.emailService = emailService;
    }

    public User registerUser(RegisterDTO registerDTO) {
        User user = new User(registerDTO.username(), registerDTO.email(), passwordEncoder.encode(registerDTO.password()));
        user.setVerificationCode(generateVerificationCode());
        user.setVerificationCodeExpiresAt(LocalDateTime.now().plusMinutes(15));
        user.setEnabled(false);
        sendVerificationEmail(user);
        return userRepository.save(user);
    }

    public User authenticateUser(LoginDTO loginDTO) {
        User user = userRepository.findByEmail(loginDTO.email())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!user.isEnabled()) {
            throw new DisabledException("Account not verified. Please verify your account.");
        }

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginDTO.email(),
                        loginDTO.password()
                )
        );

        return user;
    }

    public void verifyUser(VerifyDTO verifyDTO) {
        User user = userRepository.findByEmail(verifyDTO.email())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (user.getVerificationCodeExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Verification code has expired");
        }

        if (!user.getVerificationCode().equals(verifyDTO.verificationCode())) {
            throw new RuntimeException("Invalid verification code");
        }

        enableUser(user);
    }

    private void enableUser(User user) {
        user.setEnabled(true);
        user.setVerificationCode(null);
        user.setVerificationCodeExpiresAt(null);
        userRepository.save(user);
    }

    public void resendVerificationCode(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (user.isEnabled()) {
            throw new IllegalStateException("Account is already verified");
        }

        user.setVerificationCode(generateVerificationCode());
        user.setVerificationCodeExpiresAt(LocalDateTime.now().plusHours(1));
        sendVerificationEmail(user);
        userRepository.save(user);
    }

    private void sendVerificationEmail(User user) {
        String subject = "Account Verification";
        String htmlMessage = generateVerificationEmailContent(user.getVerificationCode());

        try {
            emailService.sendEmail(user.getEmail(), subject, htmlMessage);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    private String generateVerificationEmailContent(String verificationCode) {
        try {
            String content = new String(Files.readAllBytes(Paths.get(VERIFICATION_EMAIL_TEMPLATE_PATH)));
            return content.replace("{{verificationCode}}", verificationCode);
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    private String generateVerificationCode() {
        Random random = new Random();
        int code = random.nextInt(900000) + 100000;
        return String.valueOf(code);
    }

}

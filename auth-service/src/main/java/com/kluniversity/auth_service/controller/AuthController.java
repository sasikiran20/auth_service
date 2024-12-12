package com.kluniversity.auth_service.controller;

import com.kluniversity.auth_service.dto.LoginDTO;
import com.kluniversity.auth_service.dto.RegisterDTO;
import com.kluniversity.auth_service.dto.VerifyDTO;
import com.kluniversity.auth_service.model.User;
import com.kluniversity.auth_service.response.LoginResponse;
import com.kluniversity.auth_service.service.AuthenticationService;
import com.kluniversity.auth_service.service.JWTService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JWTService jwtService;
    private final AuthenticationService authenticationService;

    public AuthController(JWTService jwtService, AuthenticationService authenticationService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public ResponseEntity<User> signup(@RequestBody RegisterDTO registerDTO) {
        return ResponseEntity.ok(authenticationService.registerUser(registerDTO));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginDTO loginDTO) {
        User user = authenticationService.authenticateUser(loginDTO);
        String token = jwtService.generateToken(user);
        return ResponseEntity.ok(new LoginResponse(token, jwtService.getExpirationTime()));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody VerifyDTO verifyDTO) {
        try {
            authenticationService.verifyUser(verifyDTO);
            return ResponseEntity.ok("Account verified successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/resendVerification")
    public ResponseEntity<?> resendVerification(@RequestParam String email) {
        try {
            authenticationService.resendVerificationCode(email);
            return ResponseEntity.ok("Verification code sent");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

}

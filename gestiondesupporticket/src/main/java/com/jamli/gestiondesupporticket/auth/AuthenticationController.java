package com.jamli.gestiondesupporticket.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {
    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<?> register(
    @RequestBody RegisterRequest request

    ) {
        var response = service.register(request);
        if (request.isMfaEnabled()){
            return ResponseEntity.ok(response);
        }
       return ResponseEntity.accepted().build();


    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthentificationResponse> authenticate(
            @RequestBody AuthentificationRequest request
    )
    {
     return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
        HttpServletRequest request,
        HttpServletResponse  response
    )
   throws IOException{
        service.refreshToken(request,response);
    }
   @PostMapping("/verify")
    public ResponseEntity<?> verfiyCode(
     @RequestBody VerificationRequest  verificationRequest
   )
   {
       return  ResponseEntity.ok(service.verifyCode(verificationRequest));
   }
}



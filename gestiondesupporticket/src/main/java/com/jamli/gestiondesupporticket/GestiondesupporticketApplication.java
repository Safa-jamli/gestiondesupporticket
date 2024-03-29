package com.jamli.gestiondesupporticket;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication
@EnableJpaAuditing
@EnableWebMvc
@EnableSwagger2  // Enable Swagger
public class GestiondesupporticketApplication {

	public static void main(String[] args) {
		SpringApplication.run(GestiondesupporticketApplication.class, args);
	}

}

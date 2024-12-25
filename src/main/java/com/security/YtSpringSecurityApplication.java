package com.security;

import com.security.payload.RSAKeyRecord;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RSAKeyRecord.class)
public class YtSpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(YtSpringSecurityApplication.class, args);
	}

}

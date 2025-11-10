package com.detailo.identity_service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {
	"spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration",
	"spring.cloud.config.enabled=false"
})
class IdentityServiceApplicationTests {

	@Test
	void contextLoads() {
	}

}

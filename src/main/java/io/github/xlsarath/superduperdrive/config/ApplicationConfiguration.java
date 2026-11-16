package io.github.xlsarath.superduperdrive.config;

import io.github.xlsarath.superduperdrive.service.storage.BlobStore;
import io.github.xlsarath.superduperdrive.service.storage.FileSystemBlobStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.io.IOException;
import java.time.Clock;

/** Infrastructure beans: clock, blob store, JPA auditing. */
@Configuration(proxyBeanMethods = false)
@EnableJpaAuditing
public class ApplicationConfiguration {

    private static final Logger log = LoggerFactory.getLogger(ApplicationConfiguration.class);

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    BlobStore blobStore(DriveProperties properties, Clock clock) throws IOException {
        FileSystemBlobStore store = new FileSystemBlobStore(properties.storage().blobDirectory(), clock);
        log.info("Encrypted blobs are stored under the configured blob directory");
        return store;
    }
}

package io.github.xlsarath.superduperdrive;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/** SuperDuperDrive: a quantum-ready personal cloud drive. */
@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling
public class SuperDuperDriveApplication {

    public static void main(String[] args) {
        SpringApplication.run(SuperDuperDriveApplication.class, args);
    }
}

package io.github.xlsarath.superduperdrive.tls;

import io.github.xlsarath.superduperdrive.config.PqTlsConfiguration;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Starts the server with the {@code pqtls} profile restricted to the hybrid group only, then
 * proves that a client offering only {@code X25519MLKEM768} completes a TLS 1.3 handshake and
 * that a classical-only client is refused. Runs in its own JVM (failsafe {@code reuseForks=false})
 * because JSSE named-group configuration is process-wide.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "sdd.tls.named-groups=X25519MLKEM768")
@ActiveProfiles({"test", "pqtls"})
class PqTlsHandshakeIT {

    @LocalServerPort
    int port;

    @Autowired
    PqTlsConfiguration.PqTlsCertificate certificate;

    @Test
    void hybridPostQuantumKeyExchangeIsNegotiated() throws Exception {
        try (SSLSocket socket = connect("X25519MLKEM768")) {
            socket.startHandshake();
            assertThat(socket.getSession().getProtocol()).isEqualTo("TLSv1.3");

            OutputStream out = socket.getOutputStream();
            out.write(("GET /actuator/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            String response = new String(readAll(socket.getInputStream()), StandardCharsets.UTF_8);
            assertThat(response).startsWith("HTTP/1.1 200").contains("Strict-Transport-Security").contains("\"UP\"");
        }
    }

    @Test
    void classicalOnlyKeyExchangeIsRefused() throws Exception {
        try (SSLSocket socket = connect("x25519")) {
            assertThatThrownBy(socket::startHandshake).isInstanceOf(IOException.class)
                    .hasMessageContaining("handshake_failure");
        }
    }

    private SSLSocket connect(String group) throws GeneralSecurityException, IOException {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("server", certificate.certificate());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(trust);
        SSLContext context = SSLContext.getInstance("TLSv1.3", new BouncyCastleJsseProvider());
        context.init(null, tmf.getTrustManagers(), null);

        SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket("localhost", port);
        socket.setSoTimeout(10_000);
        BCSSLSocket bcSocket = (BCSSLSocket) socket;
        BCSSLParameters parameters = bcSocket.getParameters();
        parameters.setProtocols(new String[] {"TLSv1.3"});
        parameters.setNamedGroups(new String[] {group});
        bcSocket.setParameters(parameters);
        return socket;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try {
            return in.readAllBytes();
        } catch (SSLException e) {
            // Tomcat may close without close_notify after Connection: close.
            return new byte[0];
        }
    }
}

import io.jsonwebtoken.*;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.cxf.rs.security.jose.jwk.JwkUtils;
import org.apache.kafka.common.protocol.types.Field;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;
import java.util.stream.Stream;

public class test {
    public static void main(String[]args) throws IOException {
        System.out.println("hello");

        String signingKeyPath = "/tmp/public/";
        JwtParser jwtParser = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                try {
                    try(Stream<Path> path = Files.walk(new File(signingKeyPath).toPath(), 1)) {
                        return path
                                .filter((file) -> Files.isRegularFile(file) && file.getFileName().toString().endsWith(".jwk.json"))
                                .map((jwk) -> {
                                    try {
                                        JsonWebKey key = JwkUtils.readJwkSet(jwk.toUri()).getKey(header.getKeyId());
                                        return (key == null) ? null : JwkUtils.toRSAPublicKey(key);
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                        return null;
                                    }

                                })
                                .filter(Objects::nonNull)
                                .findFirst()
                                .orElse(null);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return null;
            }
        });


        String token = "eyJraWQiOiJ6M1YyaF9vUWJ5SzNjX19OeWgtYjVTaXliSDdtSnFfQV85VWlNbDZkeWNNIiwiYWxnIjoiUlMyNTYifQ.eyJjdHg6dXNlcjpkaXNwbGF5TmFtZSI6IlJvbWFpbiBHZXJhcmQiLCJjdHg6dXNlcjplbWFpbCI6InIuZ2VyYXJkQGNyaXRlby5jb20iLCJjdHg6dXNlcjp1aWQiOiJyLmdlcmFyZCIsImN0eDp1c2VyOnVtc0lkIjoiMTAyOTU1Iiwic3ViIjoidTppOnIuZ2VyYXJkQGNyaXRlby5jb20iLCJpYXQiOjE1OTEzNzE0OTQsImlzcyI6ImNyaXRlby1qdGMiLCJleHAiOjE1OTE0NTc4OTR9.rDPRyLiqBtm2RFN2ixVlJgRrA9dmMstGnBoEF3YalJWDRz8AXnZGx7hxIgJ_hGsPCG031NwfKGsgAWT4zO12WjGqsMn5MtcLZIr1ZB5CWzESV3bjimEmoI3HWCu3OuY6c6-ucS_PiqANLwILn9eMeNqQP5bp106szCXW1scO2xiFJKqs5r6XP5x0tiYgB3ade-LATKMG8MV-bAJ1m03ygte4Glh9WVN22b0EmZeAWJiPdnilouBoQwE4EO88D1CI_PcBdziVJQvLlgcsBnhW2jTqLQvj5m4pR5v89PorM-_rw75-8z0NiB7GsWPx8nLsbhEBB-Q5waYCP9jGvNdcoQ";
        Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);
        System.out.println(claimsJws);
        jwtParser.parseClaimsJws(token);
    }
}

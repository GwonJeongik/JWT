package study.jwt.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import study.jwt.entity.UserRole;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {

    //JWT 사용시 관례
    private final static String BEARER_PREFIX = "Bearer ";

    //JWT 만료 시간
    private final static Long EXPIRATION_TIME = 60 * 60 * 1000L;

    //JWT 디코딩 된 Secret Key
    private final Key secretKey;

    /* Secret Key 인코딩 -> 디코딩 생성자 */
    public JwtUtil(@Value(value = "${JWT_SECRET_KEY}") String secretKey) {
        //인코딩 된 Secret Key -> 디코딩 Byte 배열로 반환
        byte[] decodeSecretKey = Base64.getDecoder().decode(secretKey);
        //hmac-sha 알고리즘 사용 -> Key 객체 생성
        this.secretKey = Keys.hmacShaKeyFor(decodeSecretKey);
    }

    /* JWT 생성*/
    /* JWT 검증*/
    /* JWT SubString 추출*/

}

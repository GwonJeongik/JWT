package study.jwt.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import study.jwt.entity.UserRole;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {

    //Authorization Header key 값
    public final static String AUTHORIZATION_HEADER = "authorization";

    //JWT 사용시 관례
    public final static String BEARER_PREFIX = "Bearer ";

    //JWT 만료 시간
    public final static Long EXPIRATION_TIME = 60 * 60 * 1000L;

    //JWT 디코딩 된 Secret Key
    private final Key secretKey;

    /* Secret Key 인코딩 -> 디코딩 생성자 */
    public JwtUtil(@Value(value = "${JWT_SECRET_KEY}") String secretKey) {
        //인코딩 된 Secret Key -> 디코딩 Byte 배열로 반환
        byte[] decodeSecretKey = Base64.getDecoder().decode(secretKey);
        //hmac-sha 알고리즘 사용 -> Key 객체 생성
        this.secretKey = Keys.hmacShaKeyFor(decodeSecretKey);
    }

    /* JWT 생성 */
    public String createToken(Long userId, UserRole role) {
        return BEARER_PREFIX +
                Jwts.builder()
                        .setSubject(String.valueOf(userId)) //JWT 주체 설정
                        .claim("role", role) //JWT 에 담을 추가 정보
                        .setIssuedAt(new Date()) //발급일
                        .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) //만료일
                        .signWith(secretKey, SignatureAlgorithm.HS256) // 암호화 알고리즘
                        .compact(); //JWT 문자열 형태로 최종 반환
    }

    /* JWT -> Cookie 저장 */
    public void addJwtToCookie(String token, HttpServletResponse response) {
        try {
            //Cookie : 공백이 없어야함 : 공백을 %20으로 인코딩
            token = URLEncoder.encode(token, "utf-8").replace("\\+", "%20");

            Cookie cookie = new Cookie(AUTHORIZATION_HEADER, token);
            cookie.setPath("/"); //Cookie 를 받을 경로 지정

            response.addCookie(cookie); // response -> 생성한 Cookie 추가
        } catch (UnsupportedEncodingException e) {
            log.error("쿠키 인코딩 예외={}", e.getMessage(), e);
        }
    }

    /* JWT SubString 추출*/
    public Long extractSubstring(String token) {
        if (!StringUtils.hasText(token)) {
            log.error("빈 토큰={}", token);
            throw new IllegalStateException("Not Found Token");
        }

        if (!token.startsWith(BEARER_PREFIX)) {
            log.error("Bearer 로 시작하지 않음={}", token);
            throw new IllegalStateException("Not Start Bearer");
        }

        return Long.valueOf(token.substring(7));
    }


    /* JWT 검증 */


}

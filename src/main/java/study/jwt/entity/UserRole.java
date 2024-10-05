package study.jwt.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum UserRole {
    ADMIN("관리자"),
    USER("일반 사용자");

    private final String description;
}

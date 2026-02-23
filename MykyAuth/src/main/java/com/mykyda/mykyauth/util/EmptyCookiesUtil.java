package com.mykyda.mykyauth.util;

import jakarta.servlet.http.Cookie;
import lombok.experimental.UtilityClass;

import java.util.List;

@UtilityClass
public class EmptyCookiesUtil {
    public static List<Cookie> getEmptyCookies() {
        Cookie accessCookie = new Cookie("accessToken", null);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(false);
        accessCookie.setPath("/");
        accessCookie.setMaxAge(0);

        Cookie refreshCookie = new Cookie("refreshToken", null);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(false);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(0);
        return List.of(accessCookie, refreshCookie);
    }
}

package org.sid.secservice.sec;

public class JwtUtil {
    public static final String SECRET="mySecret1234";
    public static final String AUTH_HEADER="Authorization";
    public static final String HEADER_PREFIX="Bearer";
    public static final long EXPIRE_ACCESS_TOKEN=2*60*1000;
    public static final long REFRESH_TOKEN_TIMEOUT=15*60*1000;



}

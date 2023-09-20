package com.example.jwt.env.expiration;

public class ExpirationEnv {
    private final int ACCESS_TOKEN;
    private final long REFRESH_TOKEN;

    public ExpirationEnv() {
        this.ACCESS_TOKEN = 1000 * 30 * 60; // 30분
        this.REFRESH_TOKEN = 1000L * 60 * 60 * 24 * 14;
    }

    public int getACCESS_TOKEN() {
        return ACCESS_TOKEN;
    }

    public long getREFRESH_TOKEN() {
        return REFRESH_TOKEN;
    }
}

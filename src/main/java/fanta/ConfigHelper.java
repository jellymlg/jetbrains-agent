package fanta;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

public class ConfigHelper {

    public static String CERT = 
        "-----BEGIN CERTIFICATE-----\r\n" +
        "MIIEtTCCAp2gAwIBAgIUDyuccmylba71lZQAQic5TJiAhwwwDQYJKoZIhvcNAQEL\r\n" +
        "BQAwGDEWMBQGA1UEAwwNSmV0UHJvZmlsZSBDQTAeFw0yMzA5MjkxNDA2MTJaFw0z\r\n" +
        "MzA5MjcxNDA2MTJaMBExDzANBgNVBAMMBk5vdmljZTCCAiIwDQYJKoZIhvcNAQEB\r\n" +
        "BQADggIPADCCAgoCggIBALenqcGP2ZxGkYqmKA9c4Hzf8+YD1smvmOxKjd+bmTLr\r\n" +
        "utM/hXv1cj1rW3/lqyDtdDk7K6W8/TDq1CRrEt+Do6l30DxhAiC34aH8DmGwgq77\r\n" +
        "xEoLimvH5LpePxflF+tbB1RZtFgFDOIYLdSQaKFH2JDgVKxhLiV3S6jniPhkCtWW\r\n" +
        "rTs+E6vq4N15Bm3NnM5AJILqjtUbOjNfaxVq6RrOoTc0R3Fqqo6yvxo/+JYa2UnH\r\n" +
        "IC+r2dbKuDLMUrtgnydEUdJNX0zH9FtcdELvr48uc9mY038TWUsZUK1pnQbxA2bP\r\n" +
        "yA4qnYJ9IvUgO6LtLXvGFm137YQMS1N41AHDBOrwoNI8UoDX+qI3rM96biFOFvn7\r\n" +
        "Edky7rByzybt3H+zxdojfjvpL1E0NO98BT9zfufHAaAxZtlmDOu5LDJe3CGurnyR\r\n" +
        "MRExbtc+Qjl1mUh6tG4lakAwdsoxry0GdG72yaYyb9it53kaFks/T/s7Z7bRJzVF\r\n" +
        "zQDV1Y4bzUtk43vKm2vztBVlQkBkZY5f2Jbe5Ig3b8swQzBnOT0mrL5SPUhwmQ6I\r\n" +
        "xkEWztj55OEujBMmRr92oESuq9ZYMaeLidKWVR3/++HA8BRZaRGEKtSHZCbFEFdi\r\n" +
        "hDxxJv9Xh6NuT/ewJ6HYp+0NQpFnUnJ72n8wV+tudpam7aKcdzVmz7cNwOhG2Ls7\r\n" +
        "AgMBAAEwDQYJKoZIhvcNAQELBQADggIBAIdeaQfKni7tXtcywC3zJvGzaaj242pS\r\n" +
        "WB1y40HW8jub0uHjTLsBPX27iA/5rb+rNXtUWX/f2K+DU4IgaIiiHhkDrMsw7piv\r\n" +
        "azqwA9h7/uA0A5nepmTYf/HY4W6P2stbeqInNsFRZXS7Jg4Q5LgEtHKo/H8USjtV\r\n" +
        "w9apmE3BCElkXRuelXMsSllpR/JEVv/8NPLmnHSY02q4KMVW2ozXtaAxSYQmZswy\r\n" +
        "P1YnBcnRukoI4igobpcKQXwGoQCIUlec8LbFXYM9V2eNCwgABqd4r67m7QJq31Y/\r\n" +
        "1TJysQdMH+hoPFy9rqNCxSq3ptpuzcYAk6qVf58PrrYH/6bHwiYPAayvvdzNPOhM\r\n" +
        "9OCwomfcazhK3y7HyS8aBLntTQYFf7vYzZxPMDybYTvJM+ClCNnVD7Q9fttIJ6eM\r\n" +
        "XFsXb8YK1uGNjQW8Y4WHk1MCHuD9ZumWu/CtAhBn6tllTQWwNMaPOQvKf1kr1Kt5\r\n" +
        "etrONY+B6O+Oi75SZbDuGz7PIF9nMPy4WB/8XgKdVFtKJ7/zLIPHgY8IKgbx/VTz\r\n" +
        "6uBhYo8wOf3xzzweMnn06UcfV3JGNvtMuV4vlkZNNxXeifsgzHugCvJX0nybhfBh\r\n" +
        "fIqVyfK6t0eKJqrvp54XFEtJGR+lf3pBfTdcOI6QFEPKGZKoQz8Ck+BC/WBDtbjc\r\n" +
        "/uYKczZ8DKZu\r\n" +
        "-----END CERTIFICATE-----";

    public static Set<TrustAnchor> TRUST_ANCHORS;
    public static Set<String> BLOCK_URL_KEYWORDS;

    public static Set<TrustAnchor> loadTrustAnchors() throws Exception {
        if (TRUST_ANCHORS != null) {
            return TRUST_ANCHORS;
        }
        TRUST_ANCHORS = new HashSet<>();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream stream = new ByteArrayInputStream(CERT.getBytes(StandardCharsets.UTF_8));
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(stream);
        TRUST_ANCHORS.add(new TrustAnchor(cert, null));
        System.out.println("loaded " + TRUST_ANCHORS.size() + " crts");
        return TRUST_ANCHORS;
    }

    public static Set<String> loadBlockUrlKeywords() throws Exception {
        if (BLOCK_URL_KEYWORDS != null) {
            return BLOCK_URL_KEYWORDS;
        }
        BLOCK_URL_KEYWORDS = new HashSet<>();
        BLOCK_URL_KEYWORDS.add("https://account.jetbrains.com/lservice/rpc/validateKey.action");
        System.out.println("loaded " + BLOCK_URL_KEYWORDS.size() + " keywords");
        return BLOCK_URL_KEYWORDS;
    }

}
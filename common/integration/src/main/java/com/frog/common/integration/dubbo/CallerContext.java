package com.frog.common.integration.dubbo;

public final class CallerContext {
    private static final ThreadLocal<String> USER_ID = new ThreadLocal<>();
    private static final ThreadLocal<String> SERVICE = new ThreadLocal<>();

    private CallerContext() {}

    public static void set(String userId, String service) {
        USER_ID.set(userId);
        SERVICE.set(service);
    }

    public static String getUserId() { return USER_ID.get(); }
    public static String getService() { return SERVICE.get(); }
    public static void clear() { USER_ID.remove(); SERVICE.remove(); }
}

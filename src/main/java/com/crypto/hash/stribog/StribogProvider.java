package com.crypto.hash.stribog;

import java.security.Provider;

/**
 * Created by Admin on 08.09.2015.
 */
public final class StribogProvider extends Provider {

    public StribogProvider() {
        super("JStribog", 0.01, "Stribog (34.11-2012) Java implementation");
        put("MessageDigest.Stribog512", Stribog512.class.getCanonicalName());
        put("MessageDigest.Stribog256", Stribog256.class.getCanonicalName());
        put("MessageDigest.StribogB256", StribogB256.class.getCanonicalName());
        put("MessageDigest.StribogB512", StribogB512.class.getCanonicalName());
    }



}

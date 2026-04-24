package com.awahmh.decode;

import java.nio.charset.StandardCharsets;

public final class i1iIiI1iIiIiIiiI1iI {
    private i1iIiI1iIiIiIiiI1iI() {
    }

    public static String oOoooOoooOOOooo(byte[] arr_b, byte[] arr_b1) {
        return new String(i1iIiI1iIiIiIiiI1iI.xxxXXxxxxxxxXxXxXx(arr_b, arr_b1), StandardCharsets.UTF_8);
    }

    private static byte[] xxxXXxxxxxxxXxXxXx(byte[] arr_b, byte[] arr_b1) {
        int v = 0;
        for(int v1 = 0; v < arr_b.length; ++v1) {
            if(v1 >= arr_b1.length) {
                v1 = 0;
            }

            arr_b[v] = (byte)(arr_b[v] ^ arr_b1[v1]);
            ++v;
        }

        return arr_b;
    }
}

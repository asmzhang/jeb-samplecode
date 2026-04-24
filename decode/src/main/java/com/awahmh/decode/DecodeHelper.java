package com.awahmh.decode;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.lang.reflect.Method;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class DecodeHelper {
    private static final Map<String, String> TARGET_ALIASES = new HashMap<String, String>();

    static {
        String helperSig = "Lcom/awahmh/decode/i1iIiI1iIiIiIiiI1iI;->oOoooOoooOOOooo([B[B)Ljava/lang/String;";
        String mbSig = "Lcom/awahmh/decode/MBService;->oOoooOoooOOOooo([B[B)Ljava/lang/String;";
        TARGET_ALIASES.put(helperSig, helperSig);
        TARGET_ALIASES.put(mbSig, mbSig);
        TARGET_ALIASES.put("Li1iIiI1iIiIiIiiI1iI;->oOoooOoooOOOooo([B[B)Ljava/lang/String;", helperSig);
        TARGET_ALIASES.put("Lcom/mbridge/msdk/shell/MBService;->oOoooOoooOOOooo([B[B)Ljava/lang/String;", mbSig);
    }

    private DecodeHelper() {
    }

    private static byte[] parseCsvBytes(String s) {
        if(s == null || s.trim().isEmpty()) {
            return new byte[0];
        }
        String[] parts = s.split(",");
        byte[] out = new byte[parts.length];
        for(int i = 0; i < parts.length; i++) {
            int v = Integer.parseInt(parts[i].trim());
            out[i] = (byte)v;
        }
        return out;
    }

    private static String toJsonString(String s) {
        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for(int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch(c) {
            case '\\':
                sb.append("\\\\");
                break;
            case '"':
                sb.append("\\\"");
                break;
            case '\b':
                sb.append("\\b");
                break;
            case '\f':
                sb.append("\\f");
                break;
            case '\n':
                sb.append("\\n");
                break;
            case '\r':
                sb.append("\\r");
                break;
            case '\t':
                sb.append("\\t");
                break;
            default:
                if(c < 0x20) {
                    sb.append(String.format("\\u%04x", (int)c));
                }
                else {
                    sb.append(c);
                }
                break;
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static void usage() {
        System.err.println("Usage:");
        System.err.println("  java -jar decode.jar invoke --target \"Lcom/awahmh/decode/i1iIiI1iIiIiIiiI1iI;->oOoooOoooOOOooo([B[B)Ljava/lang/String;\" --arg \"118,-60,-71\" --arg \"3,-74,-43,1,25,-37,-105,32,60,101,18\"");
        System.err.println("  java -jar decode.jar serve");
    }

    public static void main(String[] args) {
        if(args.length < 1) {
            usage();
            System.exit(2);
        }

        String mode = args[0];
        String target = null;
        List<String> argValues = new ArrayList<String>();

        List<String> argv = new ArrayList<String>();
        for(int i = 1; i < args.length; i++) {
            argv.add(args[i]);
        }

        for(int i = 0; i < argv.size(); i++) {
            String arg = argv.get(i);
            if("--target".equals(arg) && i + 1 < argv.size()) {
                target = argv.get(++i);
            }
            else if("--arg".equals(arg) && i + 1 < argv.size()) {
                argValues.add(argv.get(++i));
            }
        }

        if("serve".equals(mode)) {
            serveLoop();
            return;
        }

        if(!"invoke".equals(mode) || target == null) {
            usage();
            System.exit(2);
        }

        try {
            System.out.println(invokeTarget(target, argValues));
            return;
        }
        catch(Exception e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }

    private static void serveLoop() {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
            String line;
            while((line = reader.readLine()) != null) {
                if(line.trim().isEmpty()) {
                    continue;
                }
                try {
                    String[] parts = line.split("\t", -1);
                    if(parts.length < 1) {
                        throw new IllegalArgumentException("Missing target");
                    }
                    String target = parts[0];
                    List<String> argValues = new ArrayList<String>();
                    for(int i = 1; i < parts.length; i++) {
                        argValues.add(parts[i]);
                    }
                    System.out.println(invokeTarget(target, argValues));
                }
                catch(Exception e) {
                    System.out.println("{\"type\":\"error\",\"value\":" + toJsonString(String.valueOf(e)) + "}");
                }
                System.out.flush();
            }
        }
        catch(Exception e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }

    private static String invokeTarget(String target, List<String> argValues) throws Exception {
        Dextarget parsed = parseTarget(normalizeTarget(target));
        if(parsed.paramDescriptors.size() != argValues.size()) {
            throw new IllegalArgumentException("Argument count mismatch: need " + parsed.paramDescriptors.size() + " got " + argValues.size());
        }

        Class<?> owner = Class.forName(parsed.className);
        Class<?>[] parameterTypes = new Class<?>[parsed.paramDescriptors.size()];
        Object[] invokeArgs = new Object[parsed.paramDescriptors.size()];
        for(int i = 0; i < parsed.paramDescriptors.size(); i++) {
            String descriptor = parsed.paramDescriptors.get(i);
            parameterTypes[i] = classForDescriptor(descriptor);
            invokeArgs[i] = valueForDescriptor(descriptor, argValues.get(i));
        }

        Method m = owner.getDeclaredMethod(parsed.methodName, parameterTypes);
        m.setAccessible(true);
        Object result = m.invoke(null, invokeArgs);
        return toJsonResult(parsed.returnDescriptor, result);
    }

    private static final class Dextarget {
        final String className;
        final String methodName;
        final List<String> paramDescriptors;
        final String returnDescriptor;

        Dextarget(String className, String methodName, List<String> paramDescriptors, String returnDescriptor) {
            this.className = className;
            this.methodName = methodName;
            this.paramDescriptors = paramDescriptors;
            this.returnDescriptor = returnDescriptor;
        }
    }

    private static Dextarget parseTarget(String target) {
        int p = target.indexOf("->");
        int q = target.indexOf('(', p + 2);
        int r = target.lastIndexOf(')');
        if(p < 0 || q < 0 || r < 0 || r < q) {
            throw new IllegalArgumentException("Invalid DEX target: " + target);
        }

        String classDescriptor = target.substring(0, p);
        String methodName = target.substring(p + 2, q);
        String paramsDescriptor = target.substring(q + 1, r);
        String returnDescriptor = target.substring(r + 1);

        String className = classDescriptor.substring(1, classDescriptor.length() - 1).replace('/', '.');
        List<String> params = parseParameterDescriptors(paramsDescriptor);
        return new Dextarget(className, methodName, params, returnDescriptor);
    }

    private static String normalizeTarget(String target) {
        String mapped = TARGET_ALIASES.get(target);
        return mapped != null ? mapped : target;
    }

    private static List<String> parseParameterDescriptors(String s) {
        List<String> out = new ArrayList<String>();
        int i = 0;
        while(i < s.length()) {
            int start = i;
            while(i < s.length() && s.charAt(i) == '[') {
                i++;
            }
            if(i >= s.length()) {
                throw new IllegalArgumentException("Invalid parameter descriptor: " + s);
            }
            char c = s.charAt(i);
            if(c == 'L') {
                int end = s.indexOf(';', i);
                if(end < 0) {
                    throw new IllegalArgumentException("Invalid object descriptor: " + s);
                }
                out.add(s.substring(start, end + 1));
                i = end + 1;
            }
            else {
                out.add(s.substring(start, i + 1));
                i++;
            }
        }
        return out;
    }

    private static Class<?> classForDescriptor(String descriptor) {
        switch(descriptor) {
        case "Z":
            return boolean.class;
        case "B":
            return byte.class;
        case "S":
            return short.class;
        case "I":
            return int.class;
        case "J":
            return long.class;
        case "F":
            return float.class;
        case "D":
            return double.class;
        case "Ljava/lang/String;":
            return String.class;
        case "[B":
            return byte[].class;
        default:
            throw new IllegalArgumentException("Unsupported descriptor: " + descriptor);
        }
    }

    private static Object valueForDescriptor(String descriptor, String raw) {
        switch(descriptor) {
        case "Z":
            return Boolean.parseBoolean(raw);
        case "B":
            return (byte)Integer.parseInt(raw.trim());
        case "S":
            return (short)Integer.parseInt(raw.trim());
        case "I":
            return Integer.parseInt(raw.trim());
        case "J":
            return Long.parseLong(raw.trim());
        case "F":
            return Float.parseFloat(raw.trim());
        case "D":
            return Double.parseDouble(raw.trim());
        case "Ljava/lang/String;":
            return raw;
        case "[B":
            if(raw.startsWith("base64:")) {
                return Base64.getDecoder().decode(raw.substring("base64:".length()));
            }
            return parseCsvBytes(raw);
        default:
            throw new IllegalArgumentException("Unsupported descriptor: " + descriptor);
        }
    }

    private static String toJsonResult(String returnDescriptor, Object result) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"type\":").append(toJsonString(returnDescriptor)).append(',');
        if("V".equals(returnDescriptor)) {
            sb.append("\"value\":null");
        }
        else if(result == null) {
            sb.append("\"value\":null");
        }
        else if("Ljava/lang/String;".equals(returnDescriptor)) {
            sb.append("\"value\":").append(toJsonString((String)result));
        }
        else if("[B".equals(returnDescriptor)) {
            sb.append("\"value_b64\":").append(toJsonString(Base64.getEncoder().encodeToString((byte[])result)));
        }
        else if("Z".equals(returnDescriptor) || "B".equals(returnDescriptor) || "S".equals(returnDescriptor)
                || "I".equals(returnDescriptor) || "J".equals(returnDescriptor)
                || "F".equals(returnDescriptor) || "D".equals(returnDescriptor)) {
            sb.append("\"value\":").append(String.valueOf(result));
        }
        else {
            sb.append("\"value\":").append(toJsonString(String.valueOf(result)));
        }
        sb.append('}');
        return sb.toString();
    }
}

package jpamb.cases;

public class Strings {

    public static void assertEqualManually(String s) {
        String t = "Hello World!";

        assert t.length() == s.length();

        for (int i = 0; i < t.length(); i++) {
            assert t.charAt(i) == s.charAt(i);
        }
    }

    public static void assertEqualDirectly(String s) {
        String t = "Hello World!";
        assert t.equals(s);
    }

    public static void assertConcatVars(String s) {
        String t = "Hello ";
        String u = t + s;

        assert u.equals("Hello World!");
    }

    public static void assertConcatConstants(String s) {
        String j = "Hello " + s;
        assert j.equals("Hello World!");
    }

    public static String concatA(String s) {
        return s + "A";
    }

    public static void assertReturn(String s) {
        assert concatA(s).equals("Hello World!A");
    }

    public static void assertSubstring1(int lower) {
        String s = "Hello World!";
        assert s.substring(lower).equals("World!");
    }

    public static void assertSubstring2(int lower, int higher) {
        String s = "Hello World!";
        assert s.substring(lower, higher).equals("Hello");
    }

    public static void assertIndexOfString(String source, String target, int result) {
        assert source.indexOf(target) == result;
    }

    public static void assertIndexOfChar(String source, char target, int result) {
        assert source.indexOf(target) == result;
    }

}

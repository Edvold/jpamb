package jpamb.cases;

public class Strings {

    @Case("(\"Hello World!\") -> ok")
    @Case("(\"Hello World\") -> assertion error")
    public static void assertEqualManually(String s) {
        String t = "Hello World!";

        assert t.length() == s.length();

        for (int i = 0; i < t.length(); i++) {
            assert t.charAt(i) == s.charAt(i);
        }
    }

    @Case("(\"Hello World!\") -> ok")
    @Case("(\"Hello World\") -> assertion error")
    public static void assertEqualDirectly(String s) {
        String t = "Hello World!";
        assert t.equals(s);
    }

    @Case("(\"World!\") -> ok")
    @Case("(\"World\") -> assertion error")
    public static void assertConcatVars(String s) {
        String t = "Hello ";
        String u = t + s;

        assert u.equals("Hello World!");
    }

    @Case("(\"World!\") -> ok")
    @Case("(\"World\") -> assertion error")
    public static void assertConcatConstants(String s) {
        String j = "Hello " + s;
        assert j.equals("Hello World!");
    }

    public static String concatA(String s) {
        return s + "A";
    }

    @Case("(\"Hello World!\") -> ok")
    @Case("(\"Hello World\") -> assertion error")
    public static void assertReturn(String s) {
        assert concatA(s).equals("Hello World!A");
    }

    @Case("(6) -> ok")
    @Case("(7) -> assertion error")
    @Case("(-1) -> out of bounds")
    @Case("(13) -> out of bounds")
    public static void assertSubstring1(int lower) {
        String s = "Hello World!";
        assert s.substring(lower).equals("World!");
    }

    @Case("(0, 5) -> ok")
    @Case("(0, 6) -> assertion error")
    @Case("(0, 13) -> out of bounds")
    @Case("(-1, 3) -> out of bounds")
    @Case("(5, 4) -> out of bounds")
    public static void assertSubstring2(int lower, int higher) {
        String s = "Hello World!";
        assert s.substring(lower, higher).equals("Hello");
    }

    @Case("(\"Hello World!\", \"Hello\", 0) -> ok")
    @Case("(\"Hello World!\", \"Hey\", -1) -> ok")
    public static void assertIndexOfString(String source, String target, int result) {
        assert source.indexOf(target) == result;
    }

    @Case("(\"Hello World!\", 'l', 2) -> ok")
    @Case("(\"Hello World!\", 'y', -1) -> ok")
    public static void assertIndexOfChar(String source, char target, int result) {
        assert source.indexOf(target) == result;
    }

}

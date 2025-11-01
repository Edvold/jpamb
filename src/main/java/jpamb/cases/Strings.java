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

}

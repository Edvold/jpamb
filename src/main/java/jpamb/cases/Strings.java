package jpamb.cases;

public class Strings {

    public static void assertEqual(String s) {
        String t = "Hello, World!";
        for (int i = 0; i < t.length(); i++) {
            assert t.charAt(i) == s.charAt(i);
        }
    }

}

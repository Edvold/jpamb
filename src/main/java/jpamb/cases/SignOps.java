package jpamb.cases;

import jpamb.utils.Case;

public class SignOps {

    @Case("(1, 2) -> ok")      // + +  -> +
    @Case("(-3, 5) -> ok")     // - +  -> ?
    @Case("(-2, -4) -> ok")    // - -  -> -
    @Case("(0, 7) -> ok")      // 0 +  -> +
    @Case("(0, 0) -> ok")      // 0 + 0 -> 0
    public static int add(int x, int y) {
        return x + y;
    }

    @Case("(5, 2) -> ok")      // + - + -> +
    @Case("(1, 2) -> ok")      // + - + -> -
    @Case("(5, -7) -> ok")     // + - (-) -> +
    @Case("(-3, -4) -> ok")    // - - (-) -> ?
    @Case("(0, 5) -> ok")      // 0 - + -> -
    @Case("(0, 0) -> ok")      // 0 - 0 -> 0
    public static int sub(int x, int y) {
        return x - y;
    }

    @Case("(1, 2) -> ok")      // + * + -> +
    @Case("(-3, 5) -> ok")     // - * + -> -
    @Case("(3, -4) -> ok")     // + * - -> -
    @Case("(-3, -4) -> ok")    // - * - -> +
    @Case("(0, 7) -> ok")      // 0 * + -> 0
    @Case("(0, -5) -> ok")     // 0 * - -> 0
    public static int mul(int x, int y) {
        return x * y;
    }

    @Case("(10, 2) -> ok")     // + / +  -> +
    @Case("(10, -5) -> ok")    // + / -  -> -
    @Case("(-9, 3) -> ok")     // - / +  -> -
    @Case("(-8, -2) -> ok")    // - / -  -> +
    @Case("(10, 0) -> ok")     // guarded: no divide-by-zero, returns 0
    @Case("(0, 5) -> ok")      // 0 / +  -> 0
    public static int divNoZero(int x, int y) {
        if (y == 0) {
            return 0;
        }
        return x / y;
    }
}

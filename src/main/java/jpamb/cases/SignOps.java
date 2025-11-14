package jpamb.cases;

import jpamb.utils.Case;

public final class SignOps {

  @Case("(1, 2) -> ok")
  @Case("(-3, 5) -> ok")
  public static int add(int x, int y) {
    return x + y;
  }

  @Case("(1, 2) -> ok")
  @Case("(5, -7) -> ok")
  public static int sub(int x, int y) {
    return x - y;
  }

  @Case("(1, 2) -> ok")
  @Case("(-3, -4) -> ok")
  public static int mul(int x, int y) {
    return x * y;
  }

  @Case("(10, 2) -> ok")
  @Case("(10, -5) -> ok")
  public static int divNoZero(int x, int y) {
    if (y == 0) return 0; 
    return x / y;
  }
}

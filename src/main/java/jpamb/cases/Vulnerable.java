package jpamb.cases;

import jpamb.utils.Case;

public class Vulnerable {

  @Case("('john') -> vulnerable")
  @Case("('admin OR 1=1') -> vulnerable")
  public static void simpleTainted(String a) {
    String query = "SELECT * FROM db WHERE username=" + a;

    sink(query);
  }

  @Case("('anything') -> ok")
  public static void simpleClean(String username) {
    String query = "SELECT * FROM db WHERE username='john' AND password='password';";

    sink(query);
  }

  @Case("('admin\" OR 1=1--', '') -> vulnerable")
  public static void sqlInjection(String username, String password) {
    String query = "SELECT * FROM db WHERE username='" + username +
                   "' AND password='" + password + "';";

    sink(query);
  }

  // === Dummy Sink Implementation ===
  // The sink itself does nothing meaningful.
  public static void sink(String a) {
    // No implementation
  }

}

package jpamb.cases;

import jpamb.utils.Case;

public class Vulnerable {

  // === 1. Simple tainted flow ===
  // The username and password come directly from the user and are concatenated
  // into the query string. A taint analysis should flag this.
  @Case("('john', 'password') -> vulnerable")
  @Case("('admin' OR 1=1, '') -> vulnerable")
  public void simpleTainted(String username, String password) {
    String query = "SELECT * FROM users WHERE username=" + username +
                   " AND password=" + password + ";";

    sink(query);
  }

  // === 2. Not tainted ===
  // Query is fully constant, not influenced by user input.
  @Case("('anything', 'else') -> ok")
  public void simpleClean(String username, String password) {
    String query = "SELECT * FROM users WHERE username='john' AND password='password';";

    sink(query);
  }

  // === 3. Input validated before use (not tainted in sink) ===
  // Input is checked strictly before being used in a constant query.
  @Case("('john', 'password') -> ok")
  @Case("(admin' OR 1=1--, '') -> ok")
  public void validatedSafe(String username, String password) {
    String query = "";

    if (username.equals("john") && password.equals("password")) {
      query = "SELECT * FROM users WHERE username='john' AND password='password';";
    }

    sink(query);
  }

  // === 4. SQL injection (subset of tainted) ===
  // This case uses direct concatenation *and* injection content.
  // The analysis should flag it as tainted, and possibly also classify as SQL injection.
  @Case("(admin' OR 1=1--, '') -> vulnerable")
  public void sqlInjection(String username, String password) {
    String query = "SELECT * FROM users WHERE username='" + username +
                   "' AND password='" + password + "';";

    sink(query);
  }

  // === Dummy Sink Implementation ===
  // The sink itself does nothing meaningful.
  public static void sink(String a) {
    // No implementation
  }

}

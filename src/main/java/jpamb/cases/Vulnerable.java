package jpamb.cases;

import jpamb.utils.Case;

public class Vulnerable {

  // Direct concatenation -> sink
  @Case("(\"admin\' OR 1=1; -- \") -> vulnerable")
  public static void simpleTainted(String a) {
    String query = "SELECT * FROM db WHERE username='" + a + "';";

    sink(query);
  }

  // Hardcoded string -> sink
  @Case("(\"admin\' OR 1=1; -- \") -> ok")
  public static void simpleClean(String username) {
    String query = "SELECT * FROM db WHERE username='john' AND password='password';";

    sink(query);
  }

  // Direct concatenation 2 variables -> sink
  @Case("(\"admin\' OR 1=1; -- \", \"\") -> vulnerable")
  public static void sqlInjection(String username, String password) {
    String query = "SELECT * FROM db WHERE username='" + username +
                   "' AND password='" + password + "';";

    sink(query);
  }

  // Direct concatenation -> not used in sink
  @Case("(\"admin\' OR 1=1; -- \", \"\") -> ok")
  public static void notUsed(String username, String password) {
    String query = "SELECT * FROM db WHERE username='" + username +
                   "' AND password='" + password + "';";

    sink("");
  }

  // Taint going from var to var -> sink
  @Case("(\"admin\' OR 1=1; -- \") -> vulnerable")
  public static void taintEverywhere(String username) {
    String a = username;
    String b = a;
    String c = b;
    String query = "SELECT * FROM db WHERE username='" + c + "';";

    sink(query);
  }

  // // Taint query and clean it by hardcoding after -> sink
  @Case("(\"admin\' OR 1=1; -- \") -> ok")
  public static void cleanAfterTaint(String username) {
    String query = "SELECT * FROM db WHERE username='" + username + "';";
    query = "SELECT * FROM db WHERE username='john';";
  
    sink(query);
  }

  // Tainted query -> never reaches sink
  @Case("(\"admin\' OR 1=1; -- \") -> ok")
  public static void lostTaint(String username) {
    String query = "SELECT * FROM db WHERE username='" + username + "';";

    if (0 > 1) {
      sink(query);
    }
    
  }

  // // Clean query, never becomes tainted -> sink
  @Case("(\"admin\' OR 1=1; -- \") -> ok")
  public static void cleanPathTaken(String username) {
    String query = "SELECT * FROM db WHERE username='";

    if (0 > 1) {
      query = query + username + "';";
    } else {
      query = query + "john';";
    }

    sink(query);
  }

  // Tainted query through logical flow -> sink
  @Case("(\"admin\' OR 1=1; -- \") -> vulnerable")
  public static void taintedPathTaken(String username) {
    String query = "SELECT * FROM db WHERE username='";

    if (0 < 1) {
      query = query + username + "';";
    } else {
      query = query + "john';";
    }

    sink(query);
  }

  // Several variables, one is tainted -> sink
  @Case("(\"admin\' OR 1=1; -- \") -> vulnerable")
  public static void multiConcat(String username) {
      String a = "SELECT ";
      String b = " * FROM db WHERE username='";
      String c = username + "';";
      String query = a + b + c;
      
      sink(query);
  }

  // sanitize method completely removes taint from query -> sink
  @Case("(\"admin\' OR 1=1; -- \", \"\") -> vulnerable")
  public static void semiSanitizedInput(String username, String password) {
    password = sanitize(password);
    
    String query = "SELECT * FROM db WHERE username='" + username +
                   "' AND password='" + password + "';";

    sink(query);
  }

  // sanitize method completely removes taint from user input -> sink
  @Case("(\"admin\' OR 1=1; -- \", \"\") -> ok")
  public static void sanitizedInput(String username, String password) {
    username = sanitize(username);
    password = sanitize(password);

    String query = "SELECT * FROM db WHERE username='" + username +
                   "' AND password='" + password + "';";

    sink(query);
  }

  // === Dummy Sink Implementation ===
  // The sink itself does nothing meaningful.
  public static void sink(String a) {
    // No implementation
  }

  // === Dummy Sanitizer Implementation ===
  public static String sanitize(String a) {
    return a;
  }

}

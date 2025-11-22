package jpamb.cases;

import jpamb.utils.Case;

public class LengthAbstraction {


    @Case("(0) -> ok")
    @Case("(4) -> ok")
    @Case("(5) -> out of bounds")
    @Case("(-1) -> out of bounds")
    public static void fixedLength(int i) {
        int[] a = new int[5];
        int x = a[i];
    }

    @Case("(1, 0) -> ok")            // len=1, index 0 is fine
    @Case("(3, 2) -> ok")            // len=3, last valid index
    @Case("(3, 3) -> out of bounds") // index == length
    @Case("(0, 0) -> out of bounds") // len=0, any index is OOB
    public static void lengthFromParam(int n, int i) {
        int[] a = new int[n];
        int x = a[i];
    }

    @Case("(0) -> ok")               // accesses 0 and 1
    @Case("(2) -> ok")               // accesses 2 and 3
    @Case("(3) -> out of bounds")    // 3 in range, 4 OOB
    @Case("(-1) -> out of bounds")
    public static void pairAccess(int i) {
        int[] a = new int[4];
        int x = a[i];
        int y = a[i + 1];
    }

    @Case("(2) -> ok")               // assert passes, index in bounds
    @Case("(4) -> assertion error")  // assert fails before access
    @Case("(5) -> assertion error")  // assert fails before access
    @Case("(-1) -> out of bounds")   // assert passes, then a[-1] OOB
    public static void assertProtects(int i) {
        int[] a = new int[5];
        assert i < 4;
        int x = a[i];  // executed only if assertion holds
    }

    @Case("(0) -> ok")
    @Case("(5) -> ok")
    @Case("(6) -> out of bounds")
    @Case("(-1) -> out of bounds")
    public static void lastElement(int i) {
        int[] a = new int[6];
        int last = a[a.length - 1]; 
        int x = a[i];
    }
}

package parse_and_build;

public class UnexpectedRRTypeException extends Exception {
    public UnexpectedRRTypeException() {
        super("Unexpected type of resource record");
    }
}

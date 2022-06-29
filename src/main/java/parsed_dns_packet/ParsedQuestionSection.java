package parsed_dns_packet;

public class ParsedQuestionSection implements ParsedSection {
    private final String qName;
    private final char qType, qClass;

    public ParsedQuestionSection(String qName, char qType, char qClass) {
        this.qName  = qName;
        this.qType  = qType;
        this.qClass = qClass;
    }

    public String get_qName() { return qName; }

    public char get_qType() { return qType; }

    public char get_qClass() { return qClass; }

    @Override
    public String toString() {
        return "ParsedQuestionSection{" +
                "qName='" + qName + '\'' +
                ", qType=" + qType +
                ", qClass=" + qClass +
                '}';
    }
}

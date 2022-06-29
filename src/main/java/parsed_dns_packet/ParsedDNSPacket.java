package parsed_dns_packet;

import java.util.List;

public class ParsedDNSPacket {

    private final ParsedHeader header;
    private final List<ParsedQuestionSection> question;
    private final List<ParsedRR> answer;
    private final List<ParsedRR> authority;
    private final List<ParsedRR> additional;

    public ParsedDNSPacket(ParsedHeader header, List<ParsedQuestionSection> question,
                           List<ParsedRR> answer, List<ParsedRR> authority, List<ParsedRR> additional) {
        this.header     = header;
        this.question   = question;
        this.answer     = answer;
        this.authority  = authority;
        this.additional = additional;
    }

    public ParsedHeader getHeader() { return header; }

    public List<ParsedQuestionSection> getQuestion() { return question; }

    public List<ParsedRR> getAnswer() { return answer; }

    public List<ParsedRR> getAuthority() { return authority; }

    public List<ParsedRR> getAdditional() { return additional; }

    @Override
    public String toString() {
        return "ParsedDNSPacket{\n" +
                "header=" + header +
                "\n, question=" + question +
                "\n, answer=" + answer +
                "\n, authority=" + authority +
                "\n, additional=" + additional +
                '}';
    }
}

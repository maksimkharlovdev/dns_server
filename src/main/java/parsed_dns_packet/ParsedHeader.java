package parsed_dns_packet;

public class ParsedHeader implements ParsedSection {
    private final char id, qdCount, anCount, nsCount, arCount;
    private final boolean qr, aa, tc, rd, ra;
    private final byte opcode, rCode; // actually 4-bit

    public ParsedHeader(char id, boolean qr, byte opcode,
                           boolean aa, boolean tc, boolean rd, boolean ra,
                           byte rCode, char qdCount, char anCount, char nsCount, char arCount) {
        this.id      = id;
        this.qr      = qr;
        this.opcode  = opcode;
        this.aa      = aa;
        this.tc      = tc;
        this.rd      = rd;
        this.ra      = ra;
        this.rCode   = rCode;
        this.qdCount = qdCount;
        this.anCount = anCount;
        this.nsCount = nsCount;
        this.arCount = arCount;
    }

    public byte getOpcode() { return opcode; }

    public byte get_rCode() { return rCode; }

    public char getAnCount() { return anCount; }

    public char getArCount() { return arCount; }

    public char getId() { return id; }

    public char getNsCount() { return nsCount; }

    public char getQdCount() { return qdCount; }

    public boolean getAA() { return aa; }

    public boolean getQR() { return qr; }

    public boolean getRA() { return ra; }

    public boolean getRD() { return rd; }

    public boolean getTC() { return tc; }

    @Override
    public String toString() {
        return "ParsedHeader{" +
                "id=" + id +
                ", qdCount=" + qdCount +
                ", anCount=" + anCount +
                ", nsCount=" + nsCount +
                ", arCount=" + arCount +
                ", qr=" + qr +
                ", aa=" + aa +
                ", tc=" + tc +
                ", rd=" + rd +
                ", ra=" + ra +
                ", opcode=" + opcode +
                ", rCode=" + rCode +
                '}';
    }
}

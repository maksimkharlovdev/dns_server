package rr_field_codes;

public enum RRClass {
    IN(1),  // most relevant
    CS(2),
    CH(3),
    HS(4);

    private final int m_value;

    RRClass(int value) {
        m_value = value;
    }

    public int getValue() { return m_value; }
}

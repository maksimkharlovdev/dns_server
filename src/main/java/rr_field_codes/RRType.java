package rr_field_codes;

public enum RRType {  // Типы из формулировки задачи
    A(1),
    AAAA(28),
    NS(2),
    PTR(12);

    private final int m_value;

    RRType(int value) {
        m_value = value;
    }

    public int getValue() { return m_value; }

    public static RRType getFromValue(int m_value) {
        switch (m_value) {
            case 1:
                return A;
            case 28:
                return AAAA;
            case 2:
                return NS;
            case 12:
                return PTR;
            default:
                return null;
        }
    }
}

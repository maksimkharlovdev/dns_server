package parse_and_build;

import parsed_dns_packet.ParsedDNSPacket;
import parsed_dns_packet.ParsedHeader;
import parsed_dns_packet.ParsedQuestionSection;
import parsed_dns_packet.ParsedRR;
import rr_field_codes.RRClass;
import rr_field_codes.RRType;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DNSPacketParser {
    private static int currentIndex = 0;

    public static ParsedDNSPacket parse(byte[] packet) {
        ParsedHeader header = parseHeader(packet);
        currentIndex += 12;
        List<ParsedQuestionSection> question = parseQuestionPart(packet, header.getQdCount());
        List<ParsedRR> answer = parseRRs(packet, header.getAnCount());
        List<ParsedRR> authority = parseRRs(packet, header.getNsCount());
        List<ParsedRR> additional = parseRRs(packet, header.getArCount());
        currentIndex = 0; // сбрасываем для будущих запусков

        return new ParsedDNSPacket(header, question, answer, authority, additional);
    }

    private static ParsedHeader parseHeader(byte[] packet) {
        return new ParsedHeader(
                (char) ((char) (packet[0] << 8) + packet[1]),
                (packet[2] & -0b10000000) == -128,
                (byte) ((packet[2] & 0b01111111) >> 4),
                (packet[2] & 0b100) == 4,
                (packet[2] & 0b10) == 2,
                (packet[2] & 0b1) == 1,
                (packet[3] & -0b10000000) == -128,
                (byte) (packet[3] & 0b1111),
                (char) ((char) (packet[4] << 8) + packet[5]),
                (char) ((char) (packet[6] << 8) + packet[7]),
                (char) ((char) (packet[8] << 8) + packet[9]),
                (char) ((char) (packet[10] << 8) + packet[11])
        );
    }

    private static List<ParsedQuestionSection> parseQuestionPart(byte[] fragment, int qdCount) {
        List<ParsedQuestionSection> sections = new ArrayList<>();
        for (int _i = 0; _i < qdCount; _i++){
            sections.add(
                    new ParsedQuestionSection(
                            parseByQNameRules(fragment),
                            (char) ((char) (fragment[currentIndex++] << 8) +
                                    fragment[currentIndex++]),
                            (char) ((char) (fragment[currentIndex++] << 8) +
                                    fragment[currentIndex++])
                    )
            );
        }

        return sections;
    }

    private static String parseByQNameRules(byte[] fragment) {
        StringBuilder resBuilder = new StringBuilder();
        currentIndex = writeInStringBuilderAndGetIndex(resBuilder, fragment, currentIndex);

        return resBuilder.toString();
    }

    private static int writeInStringBuilderAndGetIndex(StringBuilder sb, byte[] fragment, int index) {
        byte length;
        while (fragment[index] != 0) {
            if ((fragment[index] & -0b1000000) == -0b1000000) {  // нашли указатель
                readStringByCompressedRef(fragment, sb, index);
                index++;
                break;
            }
            length = fragment[index];
            index++;
            byte[] bytes = Arrays.copyOfRange(fragment, index, index + length);
            index += length;
            sb.append(new String(bytes, StandardCharsets.US_ASCII)).append(".");
        }
        index++;

        return index;
    }

    private static List<ParsedRR> parseRRs(byte[] fragment, int count) {
        List<ParsedRR> sections = new ArrayList<>();
        for (int _i = 0; _i < count; _i++) {
            String name = parseNamePart(fragment);
            short type = (short) ((fragment[currentIndex] << 8) + fragment[++currentIndex]);
            short clazz = (short) ((fragment[++currentIndex] << 8) + fragment[++currentIndex]);
            long ttl = (fragment[++currentIndex] << 24) + (fragment[++currentIndex] << 16) +
                    (fragment[++currentIndex] << 8) + fragment[++currentIndex];
            char rdLength = (char) ((fragment[++currentIndex] << 8) + fragment[++currentIndex]);
            String rData = null;  // Если встретили тип ресурсных записей, которые не умеем обрабатывать
            try {
                rData = parseRData(type, clazz, fragment, rdLength);
            } catch (UnexpectedRRTypeException ignored) { }

            sections.add(new ParsedRR(name, type, clazz, ttl, rdLength, rData));

        }

        return sections;
    }

    private static String parseNamePart(byte[] fragment) {
        StringBuilder resBuilder = new StringBuilder();
        if (fragment[currentIndex] == 0 && isNameFinish(fragment, currentIndex)) {
            currentIndex++;
            return resBuilder.toString();
        }
        while (fragment[currentIndex] != 0 && !isNameFinish(fragment, currentIndex)) {
            if ((fragment[currentIndex] & -0b1000000) == -0b1000000) {  // нашли указатель
                readStringByCompressedRef(fragment, resBuilder, currentIndex);
                currentIndex += 2;
            } else {
                resBuilder.append(parseByQNameRules(fragment));
            }
        }

        return resBuilder.toString();
    }

    private static void readStringByCompressedRef(byte[] fragment, StringBuilder resBuilder, int index){
        var v1 = (fragment[index] & 0b00_111111) << 8;
        var v2 = fragment[++index];
        var ref = v1 + v2;
        writeInStringBuilderAndGetIndex(
                resBuilder,
                fragment,
                ref);
    }

    private static boolean isNameFinish(byte[] fragment, int index) {
        return fragment[index] == 0 && (index + 1 >= fragment.length || fragment[index + 1] >> 1 == 0);
    }

    private static String parseRData(short type, short clazz, byte[] fragment, char len) throws UnexpectedRRTypeException {
        currentIndex++;
        StringBuilder res = new StringBuilder();
        if (clazz != RRClass.IN.getValue()) System.out.println("Unexpected class of resource record");
        if (type == (short) RRType.A.getValue()) {  // IPv4
            for (int _i = 0 ; _i < len; _i++)
                res.append(fragment[currentIndex++] & 0xff).append(".");
            res.deleteCharAt(res.length() - 1);
        } else if (type == (short) RRType.AAAA.getValue()) {  // IPv6
            for (int i = 1 ; i < len; i+=2)
                res.append(String.format("%04X", (((fragment[currentIndex + i - 1] & 0xff) << 8) & 0xffff) + (fragment[currentIndex + i] & 0xff)))
                        .append(":");
            currentIndex += len;
            res.deleteCharAt(res.length() - 1);
        } else if (type == (short) RRType.NS.getValue() || type == (short) RRType.PTR.getValue()) {
            res.append(parseByQNameRules(fragment));
        } else {
            currentIndex += len;
            throw new UnexpectedRRTypeException();
        }

        return res.toString();
    }
}
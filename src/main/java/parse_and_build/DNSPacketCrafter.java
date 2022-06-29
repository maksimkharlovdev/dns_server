package parse_and_build;

import parsed_dns_packet.ParsedDNSPacket;
import parsed_dns_packet.ParsedHeader;
import parsed_dns_packet.ParsedQuestionSection;
import parsed_dns_packet.ParsedRR;
import rr_field_codes.RRType;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class DNSPacketCrafter {
    public static byte[] craftAnswer(ParsedDNSPacket parsed) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream outputStream = new DataOutputStream(baos);
        buildHeaderToAnswer(parsed.getHeader(), outputStream);
        buildQuestionSection(parsed.getQuestion(), outputStream);
        for (ParsedRR rr : parsed.getAnswer())
            buildRR(rr, outputStream);
        for (ParsedRR rr : parsed.getAuthority())
            buildRR(rr, outputStream);
        for (ParsedRR rr : parsed.getAdditional())
            buildRR(rr, outputStream);

        return baos.toByteArray();
    }

    private static void buildHeaderToAnswer(ParsedHeader header, DataOutputStream outputStream) throws IOException {
        outputStream.writeChar(header.getId());
        int secondLine1 = -0b10000000 + (header.getOpcode() << 4) +
                (header.getAA() ? 4 : 0) + (header.getTC() ? 2 : 0) + (header.getRD() ? 1 : 0);
        int secondLine2 = (header.getRA() ? -0b10000000 : 0) +
                (header.getRA() ? header.get_rCode() : 0);
        outputStream.writeByte(secondLine1);
        outputStream.writeByte(secondLine2);
        outputStream.writeChar(header.getQdCount());
        outputStream.writeChar(header.getAnCount());
        outputStream.writeChar(header.getNsCount());
        outputStream.writeChar(header.getArCount());
    }

    private static void buildQuestionSection(List<ParsedQuestionSection> questions, DataOutputStream outputStream)
            throws IOException {
        for (ParsedQuestionSection question : questions) {
            String[] qName = question.get_qName().split("\\.");
            writeStringByQNameRules(outputStream, qName);
            outputStream.writeChar(question.get_qType());
            outputStream.writeChar(question.get_qClass());
        }
    }

    private static void buildRR(ParsedRR resourceRecord, DataOutputStream outputStream) throws IOException {
        writeStringByQNameRules(outputStream, resourceRecord.getName().split("\\."));
        outputStream.writeChar(resourceRecord.getType());
        outputStream.writeChar(resourceRecord.getClazz());
        outputStream.writeInt((int) resourceRecord.getTtl());
        outputStream.writeChar(resourceRecord.getRdLength());
        writeRData(outputStream, resourceRecord);
    }

    private static void writeStringByQNameRules(DataOutputStream outputStream, String[] strParts) throws IOException {
        for (String part : strParts) {
            outputStream.writeByte(part.length());
            for (short i = 0; i < part.length(); i++) {
                outputStream.writeByte(part.charAt(i));
            }
        }
        outputStream.writeByte(0);
    }

    private static void writeRData(DataOutputStream outputStream, ParsedRR rr) throws IOException {
        if (rr.getType() == RRType.A.getValue()) {
            writeIP(outputStream, rr.get_rData(), "\\.", 10);
        } else if (rr.getType() == RRType.AAAA.getValue()) {
            writeIP(outputStream, rr.get_rData(), ":", 16);
        } else if (rr.getType() == RRType.NS.getValue() || rr.getType() == RRType.PTR.getValue()) {  // тут может закрасться ошибка
            writeStringByQNameRules(outputStream, rr.get_rData().split("\\."));
        }

    }

    private static void writeIP(DataOutputStream outputStream, String rData, String delimiter, int radix) throws IOException {
        Integer[] parts = Arrays.stream(rData.split(delimiter))
                .map(p -> Integer.parseInt(p, radix))
                .toArray(Integer[]::new);

        if (radix == 10){
            for (Integer part : parts)
                outputStream.writeByte(part);
        } else {
            for (Integer part : parts) {
                outputStream.writeByte(part >> 8);
                outputStream.writeByte(part & 0xff);
            }
        }
    }
}

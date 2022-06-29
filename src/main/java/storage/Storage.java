package storage;

import rr_field_codes.RRType;

import java.io.Serializable;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Storage implements Serializable {
    private final Map<String, List<String>> nameWithIP;  // domain name <- IP
    private final Map<String, RRsByType> ipWithRecords;  // IP <- RR
    private long lastCheckingTime; // in seconds
    private final AtomicBoolean m_serverIsStopped;

    public Storage(AtomicBoolean serverIsStopped) {
        nameWithIP = Collections.synchronizedMap(new HashMap<>());
        ipWithRecords = Collections.synchronizedMap(new HashMap<>());
        lastCheckingTime = 0;
        m_serverIsStopped = serverIsStopped;
        startTTLChecking();
    }

    public void setServerIsStopped(boolean isStopped) { m_serverIsStopped.set(isStopped); }

    public void setDataForName(String name, String ip, RRType type, List<Record> data) {
        if (nameWithIP.containsKey(name)){
            if (!nameWithIP.get(name).contains(ip))
                ipWithRecords.put(
                        ip,
                        new RRsByType(
                                new LinkedList<>(Collections.emptyList()),
                                new LinkedList<>(Collections.emptyList()),
                                new LinkedList<>(Collections.emptyList()),
                                new LinkedList<>(Collections.emptyList())
                        )
                );
            nameWithIP.get(name).add(ip);
        } else {
            nameWithIP.put(name, new ArrayList<>(Collections.singletonList(ip)));
            ipWithRecords.put(
                    ip,
                    new RRsByType(
                            new LinkedList<>(Collections.emptyList()),
                            new LinkedList<>(Collections.emptyList()),
                            new LinkedList<>(Collections.emptyList()),
                            new LinkedList<>(Collections.emptyList())
                    )
            );
        }
        setDataForIP(ip, data, type);
    }

    private void setDataForIP(String ip, List<Record> data, RRType type) {
        if (data == null || type == null) return;
        switch (type) {
            case A:
                ipWithRecords.get(ip).typeA.addAll(data);
                break;
            case AAAA:
                ipWithRecords.get(ip).typeAAAA.addAll(data);
                break;
            case NS:
                ipWithRecords.get(ip).typeNS.addAll(data);
                break;
            case PTR:
                ipWithRecords.get(ip).typePTR.addAll(data);
                break;
            default:
                System.out.println("Unexpected type");
        }
    }

    public List<Record> getRRsByName(String name, RRType type) {
        if (!nameWithIP.containsKey(name)) return new ArrayList<>(Collections.emptyList());
        List<Record> result = new ArrayList<>();
        for (String ip : nameWithIP.get(name)) {
                List<Record> records = getRRsByIP(ip, type);
            assert records != null;
            if (records.size() == 0) continue;
                result.addAll(records);
            }

        return result;
    }

    public List<Record> getRRsByIP(String ip, RRType type) {
        if (!ipWithRecords.containsKey(ip)) return new ArrayList<>(Collections.emptyList());
         switch (type) {
             case A:
                 return ipWithRecords.get(ip).typeA;
             case AAAA:
                 return ipWithRecords.get(ip).typeAAAA;
             case NS:
                 return ipWithRecords.get(ip).typeNS;
             case PTR:
                 return ipWithRecords.get(ip).typePTR;
         }
         return new ArrayList<>(Collections.emptyList());
    }

    private static class RRsByType implements Serializable {
        private final List<Record> typeA;
        private final List<Record> typeAAAA;
        private final List<Record> typeNS;
        private final List<Record> typePTR;

        private RRsByType() {  // for serialization
            typeA = new LinkedList<>();
            typeAAAA = new LinkedList<>();
            typeNS = new LinkedList<>();
            typePTR = new LinkedList<>();
        }

        private RRsByType(List<Record> ofA, List<Record> ofAAAA,
                          List<Record> ofNS, List<Record> ofPTR) {
            typeA = ofA;
            typeAAAA = ofAAAA;
            typeNS = ofNS;
            typePTR = ofPTR;
        }

        private List<Record> getAllRecords() {
            return Stream.concat(
                    Stream.concat(typeA.stream(), typeAAAA.stream()),
                    Stream.concat(typeNS.stream(), typePTR.stream())
            ).collect(Collectors.toList());
        }
    }

    private void startTTLChecking() {
        Thread thread = new Thread(
                () -> {
                    while (!m_serverIsStopped.get()){
                        try {
                            TimeUnit.SECONDS.sleep(10);
                        } catch (InterruptedException ignored) { }

                        long delta = System.currentTimeMillis() / 1000 - lastCheckingTime;
                        deleteRecords(findRecordsToDelete(delta));
                        lastCheckingTime = System.currentTimeMillis() / 1000;
                    }
                }
        );
        thread.setDaemon(true);
        thread.start();
    }

    private HashSet<Record> findRecordsToDelete(long delta) {
        HashSet<Record> toDelete = new HashSet<>();
        synchronized (ipWithRecords) {
            for (String ip : ipWithRecords.keySet()) {
                for (Record record : ipWithRecords.get(ip).getAllRecords()) {
                    if (record.getRecord().getTtl() <= delta) {
                        toDelete.add(record);
                    } else {
                        record.getRecord().decreaseTtl(delta);
                    }
                }
            }
        }

        return toDelete;
    }

    private void deleteRecords(Set<Record> toDelete) {
        for (String ip : ipWithRecords.keySet()) {
            ipWithRecords.get(ip).typeA.removeIf(toDelete::contains);
            ipWithRecords.get(ip).typeAAAA.removeIf(toDelete::contains);
            ipWithRecords.get(ip).typeNS.removeIf(toDelete::contains);
            ipWithRecords.get(ip).typePTR.removeIf(toDelete::contains);
        }

        deleteIPs();
        deleteNames();
    }

    private void deleteIPs() {
        HashSet<String> keysToDelete = new HashSet<>();
        for (String ip : ipWithRecords.keySet()) {
            if (ipWithRecords.get(ip).typeA.size() == 0 &&
                    ipWithRecords.get(ip).typeAAAA.size() == 0 &&
                    ipWithRecords.get(ip).typeNS.size() == 0 &&
                    ipWithRecords.get(ip).typePTR.size() == 0)
                keysToDelete.add(ip);
        }

        for (String key : keysToDelete)
            ipWithRecords.remove(key);
    }

    private void deleteNames() {
        HashSet<String> ipsToDelete = new HashSet<>();
        for (String name : nameWithIP.keySet()) {
            for (String ip : nameWithIP.get(name)) {
                if (!ipWithRecords.containsKey(ip))
                    ipsToDelete.add(ip);
            }
        }

        HashSet<String> namesToDelete = new HashSet<>();
        for (String name : nameWithIP.keySet()) {
            nameWithIP.get(name).removeIf(ipsToDelete::contains);
            if (nameWithIP.get(name).size() == 0) namesToDelete.add(name);
        }

        nameWithIP.keySet().removeIf(namesToDelete::contains);

    }
}

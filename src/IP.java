import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;

class IP implements Comparable<IP>{
    private Ip4 ip;
    private String dotedDecimalIP;
    private boolean senderFlag = true; // by default we think the IP is sender's IP
    private Integer sendPacketNum = 1;
    private PcapPacket packet = null;

    IP(Ip4 ip, String dotedDecimalIP, boolean senderFlag) {
        this.ip = ip;
        this.dotedDecimalIP = dotedDecimalIP;
        this.senderFlag = senderFlag;
        this.sendPacketNum = 1;
    }

    void setSendPacketNum(int sendPacketNum) {
        this.sendPacketNum = sendPacketNum;
    }

    String getdotedDecimalIP() {
        return dotedDecimalIP;
    }

    boolean isSenderFlag() {
        return senderFlag;
    }

    int getSendPacketNum() {
        return sendPacketNum;
    }

    @Override
    public int compareTo(IP o) {
        return this.getSendPacketNum() - o.getSendPacketNum();
    }
}

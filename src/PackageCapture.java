import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * @author Bahar Kaviani
 * @version 1.0
 * @since 2021-01-01
 */
class PackageCapture extends Thread{
    private Scanner scanner = new Scanner(System.in);
    private List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
    private StringBuilder errbuf = new StringBuilder(); // For any error msgs
    private Pcap pcap = null;
    private PcapIf device = null;
    private FileHandling fileHandling;
    private int icmpCounter = 0, tcpCounter = 0, udpCounter = 0, httpCounter = 0;
    private int capturedCounter = 0, fragmentedCounter = 0;
    private ArrayList<IP> senderIPs = new ArrayList<IP>();
    private ArrayList<Integer> packectsSize = new ArrayList<Integer>();

    /**
     * The PackageCapture Constructor runs two functions
     * to find the devices and then choose one of them.
     */
    PackageCapture(FileHandling fileHandling) {
        this.fileHandling = fileHandling;
        findAndPrintAllDevices();
        chooseDevice();
    }

    /**
     * This function finds all devices connected to the Network.
     * Then print their information.
     */
    private void findAndPrintAllDevices(){
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r != Pcap.OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s",
                    errbuf.toString());
            return;
        }

        System.out.println("Network devices found:");

        int i = 0;
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null) ? device
                    .getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
                    description);
        }
    }

    /**
     * This function wants user to choose a device from listed devices.
     */
    private void chooseDevice(){
        System.out.println("choose the one device from above list of devices");
        int ch = scanner.nextInt();
        device = alldevs.get(ch);
        System.out.printf("\nChoosing '%s' on your behalf:\n",
                (device.getDescription() != null) ? device.getDescription()
                        : device.getName());
    }

    /**
     * This function captures packets until user enter any input.
     * Note that getting the input will handle with Main thread.
     */
    public void run(){
        // set snaplen, flags and timeout to initialize pcap
        setCapturingInfo();

        // Create packet handler which will receive packets
        PcapPacketHandler jpacketHandler = new PcapPacketHandler() {

            @Override
            public void nextPacket(PcapPacket packet, Object user) {

                packectsSize.add(packet.getTotalSize());
                capturedCounter++;

                byte[] data = packet.getByteArray(0, packet.size()); // the package data

                Ip4 ip = new Ip4();
                Icmp icmp = new Icmp();
                Tcp tcp = new Tcp();
                Udp udp = new Udp();
                Http http = new Http();

                if (packet.hasHeader(ip)) {

                    isIP(ip, data);

                    checkSenderIP(ip);

                    if (isFragmented(ip))
                        fragmentedCounter++;

                } else {
                    return;
                }

                if (packet.hasHeader(icmp)) {
                    System.out.println("icmp");
                    icmpCounter++;
                }
                else if (packet.hasHeader(tcp)) {
                    System.out.println("tcp");
                    tcpCounter++;

                    if (packet.hasHeader(http)) {
                        System.out.println("http");
                        httpCounter++;
                    }
                }
                else if (packet.hasHeader(udp)) {
                    System.out.println("udp");
                    udpCounter++;

                    if (packet.hasHeader(http)) {
                        System.out.println("http");
                        httpCounter++;
                    }
                }
            }
        };

        // capture first 100 packages
        pcap.loop(-1, jpacketHandler, "jNetPcap");
    }

    /**
     * This function sets all pcap.openLive function's arguments.
     */
    private void setCapturingInfo(){
        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }

        System.out.println("device opened");
    }

    /**
     *
     * @param ip
     * @param data
     */
    private void isIP(Ip4 ip, byte[] data){
        byte[] sIP = new byte[4];
        byte[] dIP = new byte[4];

        System.out.println("data:" + data);
        sIP = ip.source();
        dIP = ip.destination();

        // Use jNetPcap format utilities
        String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
        String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);

        String str = ("srcIP=" + sourceIP +
                      " dstIP=" + destinationIP);
        System.out.println(str);
    }

    /**
     * Check if the packet source ip is new or not
     * @param ip packet ip
     */
    private void checkSenderIP(Ip4 ip) {
        byte[] sIP = new byte[4];
        sIP = ip.source();
        String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);

        // check if the source is new or not
        for (IP IP: senderIPs) {
            if (IP.getdotedDecimalIP().equals(sourceIP)) {
                IP.setSendPacketNum(IP.getSendPacketNum() + 1);
                return;
            }
        }

        // the new source ip did not send anything yet
        IP newSenderIP = new IP(ip, sourceIP,  true);
        senderIPs.add(newSenderIP);
    }

    /**
     * *** work with flags
     * The function check if the packet was fragmented or not.
     * If the MF flag is mare than 0, it means More Fragment and this segment is not the last segment.
     * but if it's 0 and the offset is alse zero(which means it's the first segment)
     * so the packet wasn't segmented.
     * @param ip packet ip
     * @return true if the packet was fragmented
     */
    private boolean isFragmented(Ip4 ip) {
        int MF = ip.flags_MF();
        int offset = ip.offset();

        if (offset != 0 || MF > 0)
            return true;
        else
            return false;
    }

    /**
     * This function will stop capturing process.
     * It's called by Main thread.
     * It writes the capturing information to the file
     * Then close the file
     */
    void stopCapture(){
        pcap.breakloop();
        pcap.close();

        /* part a */
        // write number of captured packets to the captureFile.txt file
        fileHandling.writeToFile("Number of captured packets: " + capturedCounter);

        // write number of used protocols to the captureFile.txt file
        fileHandling.writeToFile("Number of ICMP packets: " + icmpCounter);
        fileHandling.writeToFile("Number of TCP packets: " + tcpCounter);
        fileHandling.writeToFile("Number of UDP packets: " + udpCounter);
        fileHandling.writeToFile("Number of HTTP packets: " + httpCounter);

        /* part b */
        //1. senderIPs SendPacketNum in ascending order
        Collections.sort(senderIPs);

        //2. senderIPs SendPacketNum in reverse order
        Collections.sort(senderIPs, Collections.reverseOrder());

        fileHandling.writeToFile("IP source addresses in descending order: ");
        System.out.println("IP source addresses in descending order: ");
        for (IP ip : senderIPs) {
            fileHandling.writeToFile("" + ip.getdotedDecimalIP() + ": " + ip.getSendPacketNum());
            System.out.println("" + ip.getdotedDecimalIP() + ": " + ip.getSendPacketNum());
        }

        /* part c */
        // write number of fragmented packets to the captureFile.txt file
        fileHandling.writeToFile("Number of fragmented packets: " + fragmentedCounter);

        /* part d */
        // packects Size in ascending order
        Collections.sort(packectsSize);

        double avgPacketSize = 0.0, sum = 0.0;

        for (Integer Psize : packectsSize) {
            sum += Psize;
        }

        avgPacketSize = sum / packectsSize.size();

        fileHandling.writeToFile("The smallest packet size: " + packectsSize.get(0));
        fileHandling.writeToFile("The largest packet size: " + packectsSize.get(packectsSize.size() - 1));
        fileHandling.writeToFile("The average packet size: " + avgPacketSize);

        /* close the file */
        try {
            fileHandling.closeFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
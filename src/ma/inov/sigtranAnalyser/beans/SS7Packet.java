package ma.inov.sigtranAnalyser.beans;

/**
 * this is the object that will englobe our packet an SS7Packet may contains any
 * type of packets, but we assume that we're using it for ss7 it contains a
 * PcapPacket object that conatins our packet (data and states) and si, opc and
 * dpc extracted from each packet
 *
 */
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.sigtran.Sctp;

import ma.inov.sigtranAnalyser.protocoles.M3uaData;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.sigtran.SctpData;

public class SS7Packet {

    private PcapPacket ss7Packet;
    private String Adaptation;
    private int si;
    private long opc;
    private long dpc;
    private int ni;
    private String ipSource;
    private String ipDestination;
    private int portSource;
    private int portDestination;
    private String VLAN;

    public SS7Packet() {
        super();
    }

    public SS7Packet(PcapPacket ss7Packet) {
        super();
        this.ss7Packet = ss7Packet;
    }

    public PcapPacket getSs7Packet() {
        return ss7Packet;
    }

    public void setSs7Packet(PcapPacket ss7Packet) {
        this.ss7Packet = ss7Packet;
    }

    public void extractRoutingLabel() {

        Ethernet eth = new Ethernet();
        Ip4 ip4 = new Ip4();
        Sctp sctp = new Sctp();
        SctpData sctpData = new SctpData();
        M3uaData m3uaData = new M3uaData();

        this.ss7Packet.hasHeader(sctpData);
        this.ss7Packet.hasHeader(ip4);
        this.ss7Packet.hasHeader(sctp);
        this.ss7Packet.hasHeader(eth);

        if (this.ss7Packet.hasHeader(m3uaData)) {
            this.Adaptation = sctpData.protocolDescription();
            this.si = m3uaData.si();
            this.opc = m3uaData.opc();
            this.dpc = m3uaData.dpc();
            this.ni = m3uaData.ni();
            this.ipSource = FormatUtils.ip(ip4.source());
            this.portSource = sctp.source();
            this.ipDestination = FormatUtils.ip(ip4.destination());
            this.portDestination = sctp.destination();
            this.VLAN = eth.typeDescription();

        }

    }
    

    public String getAdaptation() {
        return Adaptation;
    }

    public int getSi() {
        return si;
    }

    public long getDpc() {
        return dpc;
    }

    public long getOpc() {
        return opc;
    }

    public int getNi() {
        return ni;
    }

    public String getIpSource() {
        return ipSource;
    }

    public String getIpDestination() {
        return ipDestination;
    }

    public int getPortSource() {
        return portSource;
    }

    public int getPortDestination() {
        return portDestination;
    }

    public String getSiDescription() {
        switch (this.si) {
            case 3:
                return ("SCCP");
            case 5:
                return ("ISUP");
            case 7:
                return ("DUP ");
            case 13:
                return ("BICC");
            case 14:
                return ("GCP  ( H.248 )");
            default:
                return ("----");
        }
    }

    public String getVLAN() {
        return VLAN;
    }

    @Override
    public String toString() {
        return this.ss7Packet.toString();
    }

}

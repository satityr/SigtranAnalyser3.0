package ma.inov.sigtranAnalyser.protocoles;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;

@Header(length = 16, name = "M3ua-Data", description = "Protocol data (SS7 message)")
public class M3uaData extends JHeader {

    @Field(offset = 0, length = 16, display = "Parameter Tag", description = "Protocol data")
    public int tag() {
        return super.getUShort(0);
    }

    @Field(offset = 2 * 8, length = 16, display = "Parameter Length")
    public int length() {
        return super.getUShort(2);
    }

    @Field(offset = 4 * 8, length = 32)
    public long opc() {
        return super.getUInt(4);
    }

    @Field(offset = 8 * 8, length = 32)
    public long dpc() {
        return super.getUInt(8);
    }

    @Field(offset = 12 * 8, length = 8)
    public int si() {
        return super.getUByte(12);
    }

    @Field(offset = 13 * 8, length = 8)
    public int ni() {
        return super.getUByte(13);
    }

    @Field(offset = 14 * 8, length = 8)
    public int mp() {
        return super.getUByte(14);
    }

    @Field(offset = 15 * 8, length = 8)
    public int sls() {
        return super.getUByte(15);
    }

    @Dynamic(Field.Property.DESCRIPTION)
    public String siDescription() {

        switch (si()) {
            case 3: // SCCP
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
                return ("!!!!");
        }

    }

    @Bind(to = M3ua.class)
    public static boolean bindTOM3UA(JPacket packet, M3ua m3ua) {
    if (m3ua.getPayload().length < 1)
    return false; 
   
        return packet.getUByte(m3ua.getPayloadOffset()) == 2 && packet.getUByte(m3ua.getPayloadOffset() + 1) == 16 && m3ua.messageClass()==1;
    }

    @Bind(to = M3uaNetworkAp.class)
    public static boolean bindTOM3UANETWORKAP(JPacket packet, M3uaNetworkAp m3uanetworkap) {

        return packet.getUByte(m3uanetworkap.getPayloadOffset()) == 2 && packet.getUByte(m3uanetworkap.getPayloadOffset() + 1) == 16;
    }
}
package ma.inov.sigtranAnalyser.protocoles;


import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;

/**
 *
 * @author Abderrahim OUBIDAR
 */


@Header(length = 8, name = "M3ua-NetworkAp", description = "Network Appearance")
public class M3uaNetworkAp extends JHeader {

    @Field(offset = 0, length = 16, display = "Parameter Tag", description = "Network appearance")
    public int tag() {
        return super.getUShort(0);
    }

    @Field(offset = 2 * 8, length = 16, display = "Parameter Length")
    public int length() {
        return super.getUShort(2);
    }
   @Field(offset = 4 * 8, length = 32, display = "Network appearance")
    public long np() {
        return super.getUInt(4);
    }
    
@Bind(to = M3ua.class)
    public static boolean bindTOM3UA(JPacket packet, M3ua m3ua) {
if (m3ua.getPayload().length < 1)
    return false; 
   
return packet.getUByte(m3ua.getPayloadOffset())==2 && packet.getUByte(m3ua.getPayloadOffset()+1)==00 && m3ua.messageClass()==1;
    }

}

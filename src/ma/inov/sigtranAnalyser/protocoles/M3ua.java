package ma.inov.sigtranAnalyser.protocoles;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.sigtran.SctpData;


/**
 * 
 * @author Abderrahim OUBIDAR
 */

@Header(length = 8, name = "M3ua", description = "MTP 3 User Adaptation Layer", suite = ProtocolSuite.SIGTRAN)
public class M3ua extends JHeader {

    @Field(offset = 0, length = 8, display = "Version")
    public int version() {
        return super.getUByte(0);
    }

    @Field(offset = 1 * 8, length = 8, display = "Reserved", format = "%x")
    public int reserved() {
        return super.getUByte(1);
    }

    @Field(offset = 2 * 8, length = 8, display = "Message classe", format = "%d", description = "Transfer messages")
    public int messageClass() {
        return super.getUByte(2);
    }

    @Field(offset = 3 * 8, length = 8, display = "Message type", format = "%d", description = "Payload data (DATA)")
    public int messageType() {
        return super.getUByte(3);
    }

    @Field(offset = 4 * 8, length = 32, display = "Message length")
    public long messageLenght() {
        return super.getUInt(4);
    }
    
//*************Bind*************************

    @Bind(to = SctpData.class)
    public static boolean bindToSctpData(JPacket packet, SctpData data) {
        return (data.protocol() == 3);
    }

}

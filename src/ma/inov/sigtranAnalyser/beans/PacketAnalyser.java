package ma.inov.sigtranAnalyser.beans;

import static ma.inov.sigtranAnalyser.mainClasses.Main.jProgressBar1;
import static ma.inov.sigtranAnalyser.mainClasses.Main.jTable1;
import ma.inov.sigtranAnalyser.protocoles.M3ua;
import ma.inov.sigtranAnalyser.protocoles.M3uaData;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.sigtran.Sctp;
import org.jnetpcap.protocol.sigtran.SctpData;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import javax.swing.table.DefaultTableModel;
import org.jnetpcap.protocol.lan.Ethernet;

public class PacketAnalyser extends AbstractVerticle {

    DefaultTableModel model = (DefaultTableModel) jTable1.getModel();
    static int i = 0;
    String VLAN;

    Ethernet eth = new Ethernet();
    Ip4 ip4 = new Ip4();
    Sctp sctp = new Sctp();
    SctpData sctpData = new SctpData();
    M3ua m3ua = new M3ua();
    M3uaData m3uaData = new M3uaData();

    public void start(Future<Void> startFuture) {

        model.setRowCount(0);

        vertx.eventBus().consumer("com.inov.analyser", message -> {

            SS7Packet SS7PacketRecieved = (SS7Packet) message.body();

            if (SS7PacketRecieved.getSs7Packet().hasHeader(eth)) {
                if (SS7PacketRecieved.getSs7Packet().hasHeader(ip4)) {
                    if (SS7PacketRecieved.getSs7Packet().hasHeader(sctp)) {
                        if (SS7PacketRecieved.getSs7Packet().hasHeader(sctpData)) {
                            if (SS7PacketRecieved.getSs7Packet().hasHeader(m3ua)) {
                                if (SS7PacketRecieved.getSs7Packet().hasHeader(m3uaData)) {
                                    //System.out.println(SS7PacketRecieved.getSs7Packet().toString());

                                    if (eth.type() == 33024) {
                                        VLAN = eth.typeDescription();
                                    } else {
                                        VLAN = "null";
                                    }

                                    Object[] row = {
                                        sctpData.protocolDescription(),
                                        m3uaData.siDescription(),
                                        m3uaData.opc(),
                                        m3uaData.dpc(),
                                        m3uaData.ni(),
                                        FormatUtils.ip(ip4.source()),
                                        sctp.source(),
                                        FormatUtils.ip(ip4.destination()),
                                        sctp.destination(),
                                        VLAN
                                    };
                                    model.addRow(row);

                                }
                            }
                        }
                    }
                }
            }

            jProgressBar1.setValue(i++);

            if (i >= 100000) {
                i = 0;
                // jTable1.scrollRectToVisible(jTable1.getCellRect(jTable1.getRowCount() - 1, 0, true));
            }

        });

    }

}

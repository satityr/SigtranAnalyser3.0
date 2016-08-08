
package ma.inov.sigtranAnalyser.mainClasses;

import ma.inov.sigtranAnalyser.beans.OnlineCapture;
import ma.inov.sigtranAnalyser.beans.PacketAnalyser;
import ma.inov.sigtranAnalyser.beans.PacketCodec;
import static ma.inov.sigtranAnalyser.mainClasses.Main.Start_jButtoN;
import static ma.inov.sigtranAnalyser.mainClasses.Main.Stop_jButtoN;
import static ma.inov.sigtranAnalyser.mainClasses.Main.jComboBox1;
import ma.inov.sigtranAnalyser.protocoles.RegisterNewProtocole;
import io.vertx.core.Vertx;
import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;

/**
 *
 * @author BilGwiN
 */
public class ModeOffline {

    Vertx vertx;
    Pcap openFile = null;
    String file1 = null;
    StringBuilder errorMsg = null;

    public void offline() {
//------| Bottons |-----------
        Stop_jButtoN.setEnabled(true);// button stop
        Start_jButtoN.setEnabled(false);// button start
        jComboBox1.setEnabled(false);// button      

        vertx = Vertx.vertx();
        
//------| Register for Jnetpcap Protocols |------------        
        new RegisterNewProtocole().RegisterProtocoles();
        
//----------| Choose Pcap file from you pc |------------
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.showOpenDialog(null);
        File f = fileChooser.getSelectedFile();
        String filename = f.getAbsolutePath();

        errorMsg = new StringBuilder(); // For any error msgs  

        file1 = filename;
        System.out.println("opening : " + file1 + "... DONE!\n");

        openFile = Pcap.openOffline(file1, errorMsg);

        if (openFile != null) {
            // register the default codec for our eventBus
            vertx.eventBus().registerDefaultCodec(PcapPacket.class, new PacketCodec());
            //deploy our sender
            vertx.deployVerticle(new OnlineCapture(openFile));
            vertx.deployVerticle(new PacketAnalyser());

        } else {
           JOptionPane.showMessageDialog(null,"can't open file : " + file1 + "\n => " + errorMsg.toString());
        }

    }
}


package ma.inov.sigtranAnalyser.mainClasses;

import ma.inov.sigtranAnalyser.beans.Device;
import ma.inov.sigtranAnalyser.beans.OnlineCapture;
import ma.inov.sigtranAnalyser.beans.PacketAnalyser;
import ma.inov.sigtranAnalyser.beans.PacketCodec;
import static ma.inov.sigtranAnalyser.mainClasses.Main.Start_jButtoN;
import static ma.inov.sigtranAnalyser.mainClasses.Main.Stop_jButtoN;
import static ma.inov.sigtranAnalyser.mainClasses.Main.jComboBox1;
import static ma.inov.sigtranAnalyser.mainClasses.Main.jMenuOpen;
import ma.inov.sigtranAnalyser.protocoles.RegisterNewProtocole;
import io.vertx.core.Vertx;
import javax.swing.JOptionPane;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;

/**
 *
 * @author BilGwiN
 */
public class ModeLive {

    Vertx vertx;

    public void live() {

        jMenuOpen.setEnabled(false);       
        Start_jButtoN.setEnabled(false);
        Stop_jButtoN.setEnabled(true);
        jComboBox1.setEnabled(false);

        vertx = Vertx.vertx();
        // Must register our protocoles before opening the device for capture
        new RegisterNewProtocole().RegisterProtocoles();

        Device device = new Device();
        StringBuilder[] devicesToChooseFrom;

        devicesToChooseFrom = device.getDevicesListName();

        if (device.isStatus()) {

         /*   for (StringBuilder deviceInfo : devicesToChooseFrom) {

                System.out.print(deviceInfo.toString());

            }*/

            // here the user should choose an interface (device) to capture from
            // a list but for testing we will work with the wi-fi by default
            device.setChoosenDevice(devicesToChooseFrom[(int) jComboBox1.getSelectedIndex() + 1]);

            
            JOptionPane.showMessageDialog(null,"choosen device : \n"+device.getChoosenDevice().getDescription());
      

            Pcap opening = device.openDevice(device.getChoosenDevice());

            if (device.isStatus()) {

                // register the default codec for our eventBus
                vertx.eventBus().registerDefaultCodec(PcapPacket.class, new PacketCodec());

                //deploy our sender
                vertx.deployVerticle(new OnlineCapture(opening));

                // deploy our reciever
                vertx.deployVerticle(new PacketAnalyser());

            }

        } else {

            // devicesToChooseFrom[0] contains an error message
            System.out.println(devicesToChooseFrom[(int) jComboBox1.getSelectedIndex() + 1]);
        }

    }
}

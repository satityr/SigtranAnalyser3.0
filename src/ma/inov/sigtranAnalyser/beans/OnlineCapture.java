package ma.inov.sigtranAnalyser.beans;

/**
 *
 * this is the capture verticle that will be deployed to access traffic and send
 * packets to be analysed
 *
 *
 *
 */
import static ma.inov.sigtranAnalyser.mainClasses.Main.Start_jButtoN;
import static ma.inov.sigtranAnalyser.mainClasses.Main.jComboBox1;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;


public class OnlineCapture extends AbstractVerticle {

    public static Pcap openedDevice;
    public PcapPacket packetToSend;

    public OnlineCapture(Pcap pcap) {
        super();
        OnlineCapture.openedDevice = pcap;
    }

    PcapPacketHandler<PcapPacket> packetHandler = new PcapPacketHandler<PcapPacket>() {

        @Override
        public void nextPacket(PcapPacket packet, PcapPacket PermanentPacket) {

            PermanentPacket = new PcapPacket(packet);   // making a deep copy  

            vertx.eventBus().send("com.inov.analyser", PermanentPacket);

        }

    };

    public void start(Future<Void> startFuture) throws Exception {

        /* 
		 * the "loop" methode in JnetPcap's API is a blocking thread
		 * working directly with blocking code in a verticle causes exeptions
		 * therefor we use an "executeBlocking" to execute our code in the thread pool
		 * instead of the event loop and once the code executed we get either future.complete
		 * or future.failed as a result, in our case we don't care about faillure so the result part
		 * is empry
        
        */
        
        vertx.executeBlocking(future -> {
            JScanner.getThreadLocal().setFrameNumber(1);
            openedDevice.loop(Pcap.LOOP_INFINITE, packetHandler, packetToSend);

            Start_jButtoN.setEnabled(true);
            jComboBox1.setEnabled(true);

            future.complete();
        }, false, result -> {
        });

        /* other way to do so is to make the current verticle a "worker verticle"*/
        //  JScanner.getThreadLocal().setFrameNumber(1);
        // openedDevice.loop(Pcap.LOOP_INFINITE, packetHandler, packetToSend);
        //  Start_jButtoN.setEnabled(true);
        // jComboBox1.setEnabled(true);
    }

    public void stop(Future<Void> startFuture) throws Exception {

        openedDevice.close();
    }
}

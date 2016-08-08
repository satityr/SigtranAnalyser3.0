package ma.inov.sigtranAnalyser.beans;

import org.jnetpcap.packet.PcapPacket;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.eventbus.MessageCodec;


public class PacketCodec implements MessageCodec<PcapPacket, SS7Packet> {

	@Override
	public SS7Packet decodeFromWire(int position, Buffer bufferFromWire) {
		
		int lengthOfPacket = bufferFromWire.getInt(position);
		byte[] byteArrayRecievedFromWire = new byte[lengthOfPacket];
		byteArrayRecievedFromWire = bufferFromWire.getBytes(position + 4, lengthOfPacket + position + 4);
		
		return new SS7Packet(new PcapPacket(byteArrayRecievedFromWire));
	}

	@Override
	public void encodeToWire(Buffer bufferToWire, PcapPacket packetToSend) {
		
		byte[] byteArray = new byte[packetToSend.getTotalSize()];
		packetToSend.transferStateAndDataTo(byteArray);
		
		bufferToWire.appendInt(byteArray.length);
		bufferToWire.appendBytes(byteArray);
		
		
	}

	@Override
	public String name() {
		
	    // Each codec must have a unique name.
	    // This is used to identify a codec when sending a message and for unregistering codecs.
	    return this.getClass().getSimpleName();
	}

	@Override
	public byte systemCodecID() {
		
		// Used to identify system codecs. Should always return -1 for a user codec.
		return -1;
	}

	@Override
	public SS7Packet transform(PcapPacket packet) {
		
		return new SS7Packet(packet);
	}

}

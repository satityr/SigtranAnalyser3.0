package ma.inov.sigtranAnalyser.beans;

import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class Device {

	private List<PcapIf> devicesList = new ArrayList<>(); // Will be filled with
															// NICs
	private StringBuilder[] devicesListName; // Devices names and description
	private PcapIf choosenDevice;
	private boolean status; // true means OK, false means errors

	public Device() {
		super();
		this.setDevicesList();
	}

	public List<PcapIf> getDevicesList() {
		return devicesList;
	}

	@SuppressWarnings("deprecation")
	public void setDevicesList() {
		StringBuilder errbuf = new StringBuilder();

		int r = Pcap.findAllDevs(devicesList, errbuf);

		if (r == Pcap.NOT_OK || devicesList.isEmpty()) {
			devicesListName = new StringBuilder[] { new StringBuilder() };
			devicesListName[0].append("Can't read list of devices, error is "
					+ errbuf.toString());
			this.setStatus(false);
		}

		else {

			devicesListName = new StringBuilder[devicesList.size() + 1];

			devicesListName[0] = new StringBuilder("Network devices found: \n");

			int i = 1;
			for (PcapIf device : devicesList) {
				String description = (device.getDescription() != null) ? device
						.getDescription() : "No description available";
				devicesListName[i] = new StringBuilder((i++) + ": "
						+ device.getName() + " [" + description + "]\n");
			}
			this.setStatus(true);
		}
	}

	public StringBuilder[] getDevicesListName() {
		return devicesListName;
	}

	public PcapIf getChoosenDevice() {
		return choosenDevice;
	}

	public void setChoosenDevice(PcapIf choosenDevice) {
		this.choosenDevice = choosenDevice;
	}

	public void setChoosenDevice(StringBuilder choosenDeviceName) {

		if (!(devicesList.isEmpty())) {

			for (int i = 1; i < devicesListName.length; i++) {
				if (devicesListName[i].toString().equals(
						choosenDeviceName.toString())) {
					choosenDevice = devicesList.get(i-1);
					break;
				}
			}
		}
	}

	public boolean isStatus() {
		return status;
	}

	private void setStatus(boolean status) {
		this.status = status;
	}

	public Pcap openDevice(PcapIf givenDevice) {

		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 100; // 10 seconds in millis
		StringBuilder errbuf = new StringBuilder();

		Pcap pcap = Pcap.openLive(givenDevice.getName(), snaplen, flags,
				timeout, errbuf);

		if (pcap == null) {
			this.setStatus(false);
		}

		return pcap;
	}

}
package ma.inov.sigtranAnalyser.protocoles;


import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;


/**
 *
 * @author Abderrahim OUBIDAR
 */

public class RegisterNewProtocole {

	public void RegisterProtocoles(){       
		try {
		        JRegistry.register(ma.inov.sigtranAnalyser.protocoles.M3ua.class);
		        JRegistry.register(ma.inov.sigtranAnalyser.protocoles.M3uaNetworkAp.class);
		        JRegistry.register(ma.inov.sigtranAnalyser.protocoles.M3uaData.class);
		    } catch (RegistryHeaderErrors ex) {
		       
		    } 
		}
	
}

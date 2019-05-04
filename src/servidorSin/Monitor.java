package servidorSin;

import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;

public class Monitor {
	
private ArrayList<Double> cpuList;
	
	private ArrayList<Long> tiemposSolicitud;
	
	private int transacciones;
	
	public Monitor() {
		
		cpuList = new ArrayList<Double>();
		tiemposSolicitud = new ArrayList<Long>();
		transacciones = 0;
	}
	
	public ArrayList<Double> getCpuList() {
		return cpuList;
	}
	
	public ArrayList<Long> getTiemposSolicitud(){
		return tiemposSolicitud;
	}
	
	public void reportarTransaccion(){
		transacciones++;
	}
	
	public int getTransacciones(){
		return transacciones;
	}
	

	public void monitorearCPU() {
		
		double cpuUsage = 0;
		try {
			cpuUsage = getProcessCpuLoad();
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		if(cpuUsage != 0.0) {
			
			cpuList.add(cpuUsage);
			
		} else {
			try {
				TimeUnit.MILLISECONDS.sleep(1500);
				cpuUsage = getProcessCpuLoad();
				cpuList.add(cpuUsage);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public void monitorearTiempo(Long time) {
		tiemposSolicitud.add(time);
	}
	
	
	private double getProcessCpuLoad() throws Exception {

		MBeanServer mbs    = ManagementFactory.getPlatformMBeanServer();
		ObjectName name    = ObjectName.getInstance("java.lang:type=OperatingSystem");
		AttributeList list = mbs.getAttributes(name, new String[]{ "ProcessCpuLoad" });

		if (list.isEmpty())     return Double.NaN;

		Attribute att = (Attribute)list.get(0);
		Double value  = (Double)att.getValue();

		// usually takes a couple of seconds before we get real values
		if (value == -1.0)      return Double.NaN;
		// returns a percentage value with 1 decimal point precision
		return ((int)(value * 1000) / 10.0);
	}

}

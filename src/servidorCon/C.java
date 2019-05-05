package servidorCon;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.apache.poi.hssf.usermodel.HSSFCell;
import org.apache.poi.hssf.usermodel.HSSFRow;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;

public class C {
	private static ServerSocket ss;	
	private static final String MAESTRO = "MAESTRO: ";
	private static X509Certificate certSer; /* acceso default */
	private static KeyPair keyPairServidor; /* acceso default */
	private static ExecutorService  pool;
	private static Monitor monitor;

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub

		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		int ip = 8080;
		System.out.println(MAESTRO + "Empezando servidor maestro en puerto " + ip);
		System.out.println(MAESTRO + "Establezca tamaño del pool:");
		int poolSize = Integer.parseInt(br.readLine());
		System.out.println(MAESTRO + "Establezca tamaño de la carga:");
		int nPruebas = Integer.parseInt(br.readLine());
		// Adiciona la libreria como un proveedor de seguridad.
		// Necesario para crear llaves.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());		

		int idThread = 0;
		// Crea el pool de threads que responde a las solicitudes
		pool = Executors.newFixedThreadPool(poolSize);
		// Crea el socket que escucha en el puerto seleccionado.
		ss = new ServerSocket(ip);
		System.out.println(MAESTRO + "Socket creado.");

		keyPairServidor = S.grsa();
		certSer = S.gc(keyPairServidor);
		D.initCertificate(certSer, keyPairServidor);
		monitor = new Monitor();
		try { 
			while(idThread<nPruebas) {
				Socket sc = ss.accept();
				System.out.println(MAESTRO + "Cliente " + idThread + " aceptado.");
				D d = new D(sc,idThread, monitor);
				pool.execute(d);
				idThread++;
			}

		} catch (IOException e) {
			System.out.println(MAESTRO + "Error creando el socket cliente.");
			e.printStackTrace();
		}
		pool.shutdown();
		pool.awaitTermination(10000000, TimeUnit.SECONDS);

		HSSFWorkbook libro = new HSSFWorkbook();

		HSSFSheet hoja =  libro.createSheet();

		HSSFRow fila = hoja.createRow(0);

		HSSFCell celda = fila.createCell(0);

		celda.setCellValue("Tiempo");

		celda = fila.createCell(1);

		celda.setCellValue("CPU");
		
		celda = fila.createCell(2);
		
		celda.setCellValue("Transacciones Terminadas");

		for(int i = 0; i < nPruebas;i++){
			fila = hoja.createRow(i+1);
			celda =fila.createCell(0);
			celda.setCellValue(monitor.getTiemposSolicitud().get(i));
			celda = fila.createCell(1);
			celda.setCellValue(monitor.getCpuList().get(i));
			
			if(i == 0) {
				celda = fila.createCell(2);
				celda.setCellValue(monitor.getTransacciones());
			}
		}

		try{
			
			FileOutputStream file = new FileOutputStream("pruebas/DatosConSeguridad.xls");
			libro.write(file);
			file.flush();
			file.close();
			libro.close();
			
		}catch(Exception e3){
			e3.printStackTrace();
		}

		System.out.println("Numero transacciones: "+ monitor.getTransacciones());

	}



}

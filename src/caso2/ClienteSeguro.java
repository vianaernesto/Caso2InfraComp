package caso2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class ClienteSeguro {

	public static final String SERVIDOR = "localhost";

	public static void main(String args[]) throws Exception {

		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		System.out.println("Cliente CON Seguridad");
		
		System.out.println("Cliente CON Seguridad: Establezca puerto de conexion");
		Scanner port = new Scanner(System.in);
		int PUERTO = port.nextInt();
		System.out.println("Cliente CON Seguridad: Establezca id del cliente");
		int id = port.nextInt();
		port.close();

		try {
			socket = new Socket(SERVIDOR,PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		}catch(IOException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		
		ProtocoloClienteSeguro.id = id;
		
		ProtocoloClienteSeguro.procesar(stdIn,lector,escritor);
		
		stdIn.close();
		escritor.close();
		lector.close();
		socket.close();
	}
}

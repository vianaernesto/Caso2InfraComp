package caso2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.cert.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;


public class ProtocoloCliente {

	public static void procesar(BufferedReader stdIn, BufferedReader pIn,PrintWriter pOut) throws IOException {
		
		X500Name nombre = new X500Name("Infracomp");
		
		BigInteger serial = new BigInteger("1234567890");
		
		SimpleDateFormat f = new SimpleDateFormat("dd-MM-yyyy");
		
		Date notBefore = f.parse("23-03-2019");
		
		Date notAfter = f.parse("23-04-2019");
		
		X500Name subject = new X500Name("Usuario");
		
		SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(null);
		
		X509v3CertificateBuilder cert = new X509v3CertificateBuilder(nombre, serial,notBefore,notAfter,subject,);
		
		System.out.println("Escriba el mensaje para Enviar:");
		String fromUser = stdIn.readLine();
		
		pOut.println("HOLA");
		
		String fromServer="";
		
		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}
		
		pOut.println("ALGORITMOS:AES:RSA:HMACSHA1");
		
		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}
		
		
	}
}

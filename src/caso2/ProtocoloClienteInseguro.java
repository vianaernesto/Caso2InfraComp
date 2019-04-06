package caso2;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class ProtocoloClienteInseguro {
	
	public static final String SIMETRICO = "AES";
	
	public static final String ASIMETRICO = "RSA";
	
	public static final String HMAC = "HMACSHA256";
	
	public static int id;

	public static void procesar(BufferedReader stdIn, BufferedReader pIn,PrintWriter pOut) throws Exception {

		pOut.println("HOLA");

		System.out.println("Enviando HOLA al servidor");
			
		String fromServer="";

		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}

		System.out.println("Algoritmos que se van a usar:");
		System.out.println("Para manejo de confidencialidad de envio de llaves: " + ASIMETRICO);
		System.out.println("Para manejo de confidencialidad de sesion: " + SIMETRICO);
		System.out.println("Para manejo de integridad: " + HMAC);
		System.out.println("Enviando al servidor: ALGORITMOS:" + SIMETRICO + ":" + ASIMETRICO + ":" + HMAC);
		
		pOut.println("ALGORITMOS:" + SIMETRICO + ":" + ASIMETRICO + ":" + HMAC);

		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}

		// Creando llaves Asimetricas que el cliente va a utilizar
		KeyPair llaveCliente = KeyPairGenerator.getInstance(ASIMETRICO, new BouncyCastleProvider()).generateKeyPair();
		
		// Generacion del certificado
		String certificado = generarCertificado(llaveCliente);
		
		System.out.println("Enviando el certificado del cliente: " + certificado);	

		// Envio del Certificado
		pOut.println(certificado);
		
		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Certificado del Servidor: " + fromServer );
		}
		
		// Se obtiene la llave publica del servidor para generar la cadena de bytes.
		PublicKey llaveServidor = leerCertificado(fromServer).getPublicKey();		
		
		// Se crea la cadena de bytes.
		byte[] arr = llaveServidor.getEncoded();
		String cadenaBytes=DatatypeConverter.printHexBinary(arr);
		
		// Se envia la cadena.
		pOut.println(cadenaBytes);

		
		
		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Llave de sesion del Servidor: " + fromServer );
		}
		
		System.out.println("Se envia OK al Servidor");

		pOut.println("OK");
		
		//Se obtienen los datos de coordenadas.
		String gradosLatitud = String.valueOf(Math.round((Math.random() * 100)));
		String minutosLatitud = String.valueOf( Math.random() * 100);
		String gradosLongitud = String.valueOf(Math.round((Math.random() * 100)));
		String minutosLongitud = String.valueOf(Math.random() * 100);
		String msg = id + ";" + gradosLatitud + " " + minutosLatitud + "," + gradosLongitud + " " + minutosLongitud;

		System.out.println("Datos: " + msg);
		pOut.println(msg);
		pOut.println(msg);

		
		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}
		
		// Verificacion
		if(fromServer.equals(msg)) {
			System.out.println("Verificacion de contenido: OK");
		}
	}

	/**
	 * Generador de certificados
	 * @param pair Par de llaves del cliente
	 * @return Certificado
	 * @throws Exception multiples, segun la clase
	 */
	public static String generarCertificado(KeyPair pair) throws Exception
	{

		PublicKey pub = pair.getPublic();
		PrivateKey priv = pair.getPrivate();

		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
				new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), 
				new BigInteger(128, new SecureRandom()), 
				new Date(System.currentTimeMillis()), 
				new Date(System.currentTimeMillis() + 8640000000L), 
				new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), pub);
		v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pub));
		v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,	extUtils.createAuthorityKeyIdentifier(pub));


		X509Certificate certificado = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(v3CertGen.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(new BouncyCastleProvider()).build(priv)));

		byte [] certificadoEnBytes = certificado.getEncoded();		

		String respuesta= DatatypeConverter.printHexBinary(certificadoEnBytes);
		return respuesta;


	}
	
	/**
	 * Lector de certificado, obtiene un certificado X509 a partir de un certificado String.
	 * @param str Certificado en forma de string.
	 * @return X509 certificado.
	 * @throws Exception
	 */
	public static X509Certificate leerCertificado(String str) throws Exception
	{
		byte[] certificadoEnBytes= DatatypeConverter.parseHexBinary(str);	
		X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new X509CertificateHolder(certificadoEnBytes));
		return cert;
	}
}

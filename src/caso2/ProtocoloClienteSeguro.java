package caso2;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
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



public class ProtocoloClienteSeguro {
	
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
		
		// Se obtiene la llave publica del servidor mediante el certificado.
		PublicKey llaveServidor = leerCertificado(fromServer).getPublicKey();
		
		// Se crea el par de llaves de servidor para utilizar en la desencripcion
		KeyPair parServidor= new KeyPair(llaveServidor,null);

		// Se crea la llave de sesion
		byte[] arr = new byte[32];
		SecretKey sesion = new SecretKeySpec(arr,SIMETRICO);
		
		// Se cifra la llave de sesion con la llave publicad del servidor.
		String llaveCifrada= DatatypeConverter.printHexBinary(cifradoAsimetrico(llaveServidor,sesion.getEncoded()));
		
		System.out.println("Enviando llave de sesion encriptada con llave publica del servidor:" + llaveCifrada);	
		
		// Enviando al servidor.
		pOut.println(llaveCifrada);
		
		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor, llave de sesion encriptada con llave publica del cliente: " + fromServer );
		}
		
		//Convirtiendo la llave de sesion cifrada recibida a byte[]
		byte[] llaveServidorCifrada= DatatypeConverter.parseHexBinary(fromServer);
		
		// Se descifra la llave de sesion para utilizarse en el intercambio de datos.
		SecretKey llaveLS=new SecretKeySpec(descifradoAsimetrico(llaveCliente,llaveServidorCifrada,"privada"),SIMETRICO);

		System.out.println("Se envia OK al Servidor");
		
		pOut.println("OK");
		
		//Se obtienen los datos de coordenadas.
		String gradosLatitud = String.valueOf(Math.round((Math.random() * 100)));
		String minutosLatitud = String.valueOf( Math.random() * 100);
		String gradosLongitud = String.valueOf(Math.round((Math.random() * 100)));
		String minutosLongitud = String.valueOf(Math.random() * 100);
		String msg = id + ";" + gradosLatitud + " " + minutosLatitud + "," + gradosLongitud + " " + minutosLongitud;

		System.out.println("Datos: " + msg);
		
		// Se encriptan los datos.
		byte[] coordenadasEncriptadas = cifradoSimetricoAES(llaveLS,msg.getBytes());
		
		// se obtiene el codigo de autenticacion dado el mensaje y las llaves.
		byte[] codigoAutenticacion = hmac(msg.getBytes(),llaveLS, HMAC);

		// se obtienen su version hexadecimal
		String criptoStr= DatatypeConverter.printHexBinary(coordenadasEncriptadas);
		String hmacStr= DatatypeConverter.printHexBinary(codigoAutenticacion);

		System.out.println("Se envian los datos encriptados con la llave de sesion: " + criptoStr);
		System.out.println("Se envia el codigo de autenticacion HMAC " + hmacStr);
		
		//Se envian al servidor.
		pOut.println(criptoStr);
		pOut.println(hmacStr);
		
		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}
		
		System.out.println("Se recibe el codigo de autenticacion cifrado con la llave privada del servidor");
		
		// Se convierte la respuesta del servidor.
		byte[] respuestaServidor = DatatypeConverter.parseHexBinary(fromServer);
		// Se obtiene el codigo de autenticacion
		byte[] hmacRespuesta= descifradoAsimetrico(parServidor,respuestaServidor,"publica");
		

		
		if(Arrays.equals(hmacRespuesta, codigoAutenticacion)) {
			System.out.println("Verificacion de integridad: OK");
		}
		
	}

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

	public static X509Certificate leerCertificado(String str) throws Exception
	{
		byte[] certificadoEnBytes= DatatypeConverter.parseHexBinary(str);	
		X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new X509CertificateHolder(certificadoEnBytes));
		return cert;
	}
	
	public static byte[] cifradoAsimetrico(PublicKey llave, byte[] msg) throws Exception {
		Cipher cipher = Cipher.getInstance(ASIMETRICO);
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		return cipher.doFinal(msg);
	}
	
	public static byte[] descifradoAsimetrico(KeyPair llave, byte[] msg,String tipoLlave) throws Exception {
		
		byte[] descifrado = null;
		if(tipoLlave.equals("privada")) {
		Cipher cipher = Cipher.getInstance(ASIMETRICO);
		cipher.init(Cipher.DECRYPT_MODE, llave.getPrivate());
		descifrado = cipher.doFinal(msg);
		} else if (tipoLlave.equals("publica")){
			Cipher cipher = Cipher.getInstance(ASIMETRICO);
			cipher.init(Cipher.DECRYPT_MODE, llave.getPublic());
			descifrado = cipher.doFinal(msg);
		}
		return descifrado;
	}
	
	public static byte[] cifradoSimetricoAES(SecretKey llave, byte[] clearText) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		return cipher.doFinal(clearText);
	}
	
	public static byte[] descifradoSimetricoAES(SecretKey llave, byte[] msg) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, llave);
		return cipher.doFinal(msg);
	}
	
	private static byte[] hmac(byte[] msg, SecretKey key, String alg) throws Exception {
		Mac mac = Mac.getInstance(alg);
		mac.init(key);
		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}
	

}

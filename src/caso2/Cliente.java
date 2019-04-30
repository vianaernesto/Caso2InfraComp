package caso2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
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

public class Cliente {

	public static final String SERVIDOR = "localhost";

	public static final String SIMETRICO = "AES";

	public static final String ASIMETRICO = "RSA";

	public static final String HMAC = "HMACSHA256";

	public static int id;

	/**
	 * SEGURO 
	 * NOSEGURO
	 */
	public static String SEGURIDAD = "NOSEGURO";

	public static void main(String args[]) throws Exception {

		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		System.out.println("Cliente SIN/CON Seguridad: Establezca puerto de conexion");
		Scanner port = new Scanner(System.in);
		int PUERTO = port.nextInt();
		System.out.println("Cliente SIN/CON Seguridad: Establezca el id del cliente.");
		int idx = port.nextInt();
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

		id	= idx;

		if(SEGURIDAD == "SEGURO")
			procesarSeguro(stdIn,lector,escritor);
		else
			procesarInseguro(stdIn,lector,escritor);

		stdIn.close();
		escritor.close();
		lector.close();
		socket.close();
	}

	public static void procesarSeguro(BufferedReader stdIn, BufferedReader pIn,PrintWriter pOut) throws Exception {

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
		byte[] codigoVerificacionRecibido= descifradoAsimetrico(parServidor,respuestaServidor,"publica");

		System.out.println("Codigo de Verificacion recibido: " + DatatypeConverter.printHexBinary(codigoVerificacionRecibido));

		// Verificacion de integridad
		if(Arrays.equals(codigoVerificacionRecibido, codigoAutenticacion)) {
			System.out.println("Verificacion de integridad: OK");
		}

	}

	public static void procesarInseguro(BufferedReader stdIn, BufferedReader pIn,PrintWriter pOut) throws Exception {

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

	/**
	 * Cifra un mensaje Asimetricamente con el algoritmo RSA
	 * @param llave, llave con la que se va a cifrar
	 * @param msg mensaje que se va a cifrar
	 * @return mensaje cifrado.
	 * @throws Exception excepciones de cipher
	 */
	public static byte[] cifradoAsimetrico(PublicKey llave, byte[] msg) throws Exception {
		Cipher cipher = Cipher.getInstance(ASIMETRICO);
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		return cipher.doFinal(msg);
	}

	/**
	 * Descifra un mensaje a partir de la llave y el mensaje y un tipoLlave asimetricamente, 
	 * con el algoritmo RSA.
	 * @param llave par de llaves de las cuales se va a utilizar una llave (publica o privada)
	 * @param msg mensaje que se va a descifrar.
	 * @param tipoLlave tipo de llave que se va a utilizar, publica o privada.
	 * @return mensaje descifrado.
	 * @throws Exception excepciones de cipher.
	 */
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

	/**
	 * Cifra simetricamente con el algoritmo AES.
	 * @param llave, llave con la cual se va a cifrar.
	 * @param clearText mensaje que se va a encriptar.
	 * @return mensaje cifrado
	 * @throws Exception excepciones de cipher.
	 */
	public static byte[] cifradoSimetricoAES(SecretKey llave, byte[] clearText) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		return cipher.doFinal(clearText);
	}

	/**
	 * Descifra simetricamente con el algoritmo AES.
	 * @param llave, llave con la cual se va a descifrar.
	 * @param clearText mensaje que se va a desencriptar.
	 * @return mensaje cifrado
	 * @throws Exception excepciones de cipher.
	 */
	public static byte[] descifradoSimetricoAES(SecretKey llave, byte[] msg) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, llave);
		return cipher.doFinal(msg);
	}

	/**
	 * Metodo que genera el codigo de verificacion de integridad HMAC
	 * @param msg mensaje del cual se va a obtener el codigo.
	 * @param key llave con la cual se genera el codigo.
	 * @param alg algoritmo que se va a usar.
	 * @return codigo de verificacion de integridad.
	 * @throws Exception excepciones de mac.
	 */
	private static byte[] hmac(byte[] msg, SecretKey key, String alg) throws Exception {
		Mac mac = Mac.getInstance(alg);
		mac.init(key);
		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}
}

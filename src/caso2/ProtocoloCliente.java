package caso2;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
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



public class ProtocoloCliente {

	public static void procesar(BufferedReader stdIn, BufferedReader pIn,PrintWriter pOut) throws Exception {

		pOut.println("HOLA");

		String fromServer="";

		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}

		pOut.println("ALGORITMOS:AES:RSA:HMACSHA1");

		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}

		KeyPair llaveCliente = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider()).generateKeyPair();
		pOut.println(generarCertificado(llaveCliente));

		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}
		
		PublicKey llaveServidor = leerCertificado(fromServer).getPublicKey();


		byte[] arr = new byte[32];
		SecretKey sesion = new SecretKeySpec(arr,"AES");
		
		String llaveCifrada= DatatypeConverter.printHexBinary(cifradoAsimetrico(llaveServidor,sesion.getEncoded()));
		pOut.println(llaveCifrada);
		
		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}
		
		byte[] llaveServidorCifrada= DatatypeConverter.parseHexBinary(fromServer);
		SecretKey llaveLS=new SecretKeySpec(descifradoAsimetrico(llaveCliente,llaveServidorCifrada),"AES");
		
		System.out.println("Escriba la coordenada: ");
		Scanner cordenadas= new Scanner(System.in);
		String msg =cordenadas.nextLine(); 
		cordenadas.close();
		
		byte[] coordenadasEncriptadas = cifradoSimetricoAES(llaveLS,msg.getBytes());
		//byte[] msgEnBytesEncriptados= cifradoSimetricoBlowfish(llaveLS,msg.getBytes());
		
		byte[] coordenadasHMAC = hmac(msg.getBytes(),llaveLS, "HMACMD5");

		String criptoStr= DatatypeConverter.printHexBinary(coordenadasEncriptadas);
		String hmacStr= DatatypeConverter.printHexBinary(coordenadasHMAC);
		
		pOut.println("OK");
		pOut.println(criptoStr);
		pOut.println(hmacStr);
		
		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
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
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		return cipher.doFinal(msg);
	}
	
	public static byte[] descifradoAsimetrico(KeyPair llave, byte[] msg) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, llave.getPrivate());
		return cipher.doFinal(msg);
	}
	
	public static byte[] cifradoSimetricoAES(SecretKey llave, byte[] clearText) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		return cipher.doFinal(clearText);
	}
	
	public static byte[] cifradoSimetricoBlowfish(SecretKey llave, byte[] clearText) throws Exception {
		Cipher cipher = Cipher.getInstance("Blowfish");
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		return cipher.doFinal(clearText);
	}
	
	private static byte[] hmac(byte[] msg, SecretKey key, String alg) throws Exception {
		Mac mac = Mac.getInstance(alg);
		mac.init(key);
		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}
	

}

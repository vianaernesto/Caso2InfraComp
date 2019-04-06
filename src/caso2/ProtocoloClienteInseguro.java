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

		byte[] arr = new byte[128];
		String cadenaBytes=DatatypeConverter.printHexBinary(arr);
		pOut.println(cadenaBytes);

		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}

		System.out.println("Escriba la coordenada: ");
		Scanner cordenadas= new Scanner(System.in);
		String msg =cordenadas.nextLine(); 
		cordenadas.close();

		pOut.println("OK");
		pOut.println(msg);
		pOut.println(msg);

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
}

package caso2;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;



public class ProtocoloCliente {

	public static void procesar(BufferedReader stdIn, BufferedReader pIn,PrintWriter pOut) throws Exception {
				
		
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
		
		KeyPair keyClient = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider()).generateKeyPair();
		pOut.println(generarCertificado(keyClient));
		
		if((fromServer = pIn.readLine())!= null) {
			System.out.println("Respuesta del Servidor: " + fromServer );
		}
		
		byte[] arr = new byte[32];
		SecretKey llaveS = new SecretKeySpec(arr,"AES");
		//String llaveCifrada= DatatypeConverter.printHexBinary(cifrarAsimetrico(llaveS.getEncoded()));
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

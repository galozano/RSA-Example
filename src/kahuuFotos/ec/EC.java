package kahuuFotos.ec;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;


public class EC 
{

	private ServerSocket socket;

	private RSA2 rsa;
	
	private X509Certificate certificadoPropio;


	public EC()
	{
		rsa = new RSA2();
	}

	public void generarClaves() throws KahuuException
	{
		rsa.generarClaves();
		certificadoPropio = generateV3Certificate("KAHUU FOTOS EC", rsa.darLLavePublica());
	}

	public X509Certificate darCertificadoPropio()
	{
		return certificadoPropio;
	}
	
	public void guardarClaves() throws KahuuException
	{
		try
		{	
			FileOutputStream fileOut=new FileOutputStream("data/salvado.obj");
			ObjectOutputStream salida=new ObjectOutputStream(fileOut);

			salida.writeObject(rsa);
			salida.writeObject(certificadoPropio);

			salida.flush();
			salida.close();
			fileOut.close();
		}
		catch (Exception e) 
		{
			throw new KahuuException("Error:"+ e.getMessage());
		}
	}

	public void leerClaves() throws KahuuException
	{
		try
		{
			FileInputStream fileIn = new FileInputStream("data/salvado.obj");
			ObjectInputStream entrada=new ObjectInputStream(fileIn);

			rsa = (RSA2) entrada.readObject();
			certificadoPropio = (X509Certificate) entrada.readObject();
			
			entrada.close();
			fileIn.close();

		}
		catch (Exception e) 
		{
			throw new KahuuException("Error:"+ e.getMessage());
		}
	}

	public RSA2 darRSA()
	{
		return rsa;
	}

	public void run() throws KahuuException
	{
		try 
		{

			socket = new ServerSocket(9999);

			while(true)
			{
				System.out.println("ESPERANDO...");
				Socket entrada = socket.accept();

				ThreadEC thread = new ThreadEC(entrada.getInputStream(),entrada.getOutputStream(), this);
				thread.run();
			}     
		}
		catch (Exception e) 
		{
			throw new KahuuException("Error:"+ e.getMessage());
		}
	}


	public PublicKey generarLLavePublica(byte[] publica) throws KahuuException
	{
		try 
		{
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publica));
			return publicKey;
		} 
		catch (InvalidKeySpecException e) 
		{
			throw new KahuuException("Error:"+ e.getMessage());		
		} 
		catch (NoSuchAlgorithmException e)
		{
			throw new KahuuException("Error:"+ e.getMessage());
		}
	}



	@SuppressWarnings("deprecation")
	public X509Certificate generateV3Certificate(String emailDelCertificador, PublicKey llavePublica) throws  KahuuException 
	{
		try 
		{
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

			certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
			certGen.setIssuerDN(new X500Principal("CN=Certificado Kahuu Foto"));
			certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
			certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
			certGen.setSubjectDN(new X500Principal("CN=Kahuu Certificate"));

			certGen.setPublicKey(llavePublica);	
			certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

			certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
			certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature| KeyUsage.keyEncipherment));
			certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
			certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, emailDelCertificador)));

			return certGen.generateX509Certificate(rsa.darLLavePrivada());
		} 
		catch (InvalidKeyException e)
		{
			throw new KahuuException("Error:"+ e.getMessage());
		} 
		catch (SecurityException e) 
		{
			throw new KahuuException("Error:"+ e.getMessage());
		} 
		catch (SignatureException e) 
		{
			throw new KahuuException("Error:"+ e.getMessage());
		}
	}

	public static String asHex (byte buf[]) 
	{
		StringBuffer strbuf = new StringBuffer(buf.length * 2);
		int i;

		for (i = 0; i < buf.length; i++) {
			if (((int) buf[i] & 0xff) < 0x10)
				strbuf.append("0");

			strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
		}

		return strbuf.toString();
	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

	/**
	 * @param args
	 * @throws KahuuException 
	 */
	public static void main(String[] args) throws KahuuException 
	{
		EC ec = new EC();
		//ec.generarClaves();
		//ec.guardarClaves();
		
		ec.leerClaves();
		ec.run();
	}

}

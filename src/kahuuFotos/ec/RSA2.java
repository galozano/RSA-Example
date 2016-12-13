package kahuuFotos.ec;


import java.io.Serializable;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;


public class RSA2 implements Serializable
{	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private PrivateKey privateKey;
	
	private PublicKey publicKey;
	
	public void generarClaves() throws KahuuException
	{	
		try 
		{
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);  
			KeyPair key = keyPairGenerator.generateKeyPair();  
			
			privateKey = key.getPrivate();
			publicKey =  key.getPublic();
		} 
		catch (NoSuchAlgorithmException e) 
		{
			throw new KahuuException(e.getMessage());
		}  

	}

	public byte[] encripta(byte[] mensaje, Key publicaOtro) throws KahuuException
	{
		try
		{
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicaOtro);
			
			byte[] cipherData = cipher.doFinal(mensaje);
			//byte[] cipherData = blockCipher(mensaje,Cipher.ENCRYPT_MODE,cipher);
	
			return cipherData;
		}
		catch (Exception e)
		{
			throw new KahuuException(e.getMessage());
		}
	}
	
	
	public byte[] desencripta(byte[] mensaje) throws KahuuException
	{
		try
		{
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			
			byte[] cipherData = cipher.doFinal(mensaje);
			//byte[] cipherData = blockCipher(mensaje,Cipher.DECRYPT_MODE,cipher);
			
			return cipherData;
		}
		catch (Exception e)
		{
			throw new KahuuException("Error Enciptando:"+ e.getMessage());
		}
	}
	
	public byte[] desencriptarPersonalizado(byte[] mensaje, Key llave) throws KahuuException
	{
		try
		{
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, llave);
			
			byte[] cipherData = cipher.doFinal(mensaje);
			
			return cipherData;
		}
		catch (Exception e)
		{
			throw new KahuuException("Error Enciptando:"+ e.getMessage());
		}
	
	}
	
	public PublicKey darLLavePublica()
	{
		return publicKey;
	}
	
	public PrivateKey darLLavePrivada()
	{
		return privateKey;
	}
	
	public void asignarLLavePublica(PublicKey publica)
	{
		publicKey = publica;
	}
	
	public void asignarLLavePrivada(PrivateKey privada)
	{
		privateKey = privada;
	}
}

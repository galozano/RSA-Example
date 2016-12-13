package kahuuFotos.ec;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class ThreadEC extends Thread
{

	private  OutputStream out;
	private InputStream in;
	private EC ec;
	
	
	public ThreadEC(InputStream in, OutputStream out, EC ec)
	{
		this.in = in;
		this.out = out;
		this.ec = ec;
	}
	@Override
	public void run()
	{         	            

		try
		{
			byte[] buffer = new byte[2000];
			
			//LEER NOMBRE
			byte[] mensaje = leerMensaje(buffer);  		
			System.out.println(EC.asHex(mensaje));
			String nombre = new String(mensaje);
			System.out.println("NOMBRE:"+ nombre);
			
			//LEER CLAVE PUBLICA
			byte[] mensaje2 = leerMensaje(buffer);  
			System.out.println("PUBLICA ENCODED:" + EC.asHex(mensaje2));
			PublicKey publicKey = ec.generarLLavePublica(mensaje2);

			//Se genera el certificado
			X509Certificate certificado = ec.generateV3Certificate(nombre, publicKey);
			System.out.println("CERTIFICADO:" + EC.asHex(certificado.getEncoded()));

			//Manda el Certificado Creado del Nodo
			out.write(certificado.getEncoded());
			out.flush();
			
			Thread.sleep(1000);
			
			//Manda el certificado del EC
			System.out.println("CERTIFICADO EC PROPIO:" + EC.asHex(ec.darCertificadoPropio().getEncoded()));
			out.write(ec.darCertificadoPropio().getEncoded());
			out.flush();
			
			out.close();
			in.close();
		}
		catch (Exception e) 
		{
			e.printStackTrace();
		}
		
	}
	
	private byte[] leerMensaje(byte[] buffer ) throws KahuuException
	{
		int datos=-1;
		try 
		{
			System.out.println("LEER");
			datos=in.read(buffer);

			byte[] buffer2= new byte[datos];

			for (int i = 0; i < datos; i++) 
			{
				buffer2[i]=buffer[i];
			}
			
			return buffer2;

		} 
		catch (Exception e) 
		{
			throw new KahuuException("Error:"+ e.getMessage());
		}	
	}
	
}

package kahuuFotos.ec;
 
public class KahuuException extends Exception
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	
    //------------------------------------------------------------------------------------------------------------------------------
    // Constructores
    //------------------------------------------------------------------------------------------------------------------------------
	
	/**
	 * 
	 * @param mensaje
	 */
	public KahuuException(String mensaje)
	{
		super(mensaje);
		
	}
}

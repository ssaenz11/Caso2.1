package Cliente;
import java.awt.FontFormatException;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class Cliente extends Thread
{
	// constantes Socket
	public final static String HOST ="localhost";
	public final static int puerto =5000;

	// Constantes de encriptación
	public final static String AES = "AES";
	public final static String BLOWFISH = "BLOWFISH";
	public final static String RSA = "RSA";
	public final static String HMACMD5 = "HMACMD5";
	public final static String HMACSHA1 = "HMACSHA1";
	public final static String HMACSHA256 = "HMACSHA256";

	//Constantes de comunicación
	public final static String CERTIFICADO = "CERTCLNT";
	public final static String ALGORITMOS = "ALGORITMOS:"+AES+":"+RSA+":"+HMACMD5;
	public final static String OK = "ESTADO:OK";
	public final static String ERROR = "ESTADO:ERROR";
	public final static String INICIO = "INICIO";
	public final static String CERRAR = "Cerrando conexión";
	public final static String ACT1 = "ACT1";
	public final static String ACT2 = "ACT2";


	public final static String SERV = "SERVIDOR: ";
	public final static String CLI = "CLIENTE: ";


	//Atributos del socket
	boolean ejecutar = true;
	Socket socket = null; 
	PrintWriter escritor = null; 
	BufferedReader lector = null;

	//llave
	private KeyPair keyPair;
	private X509Certificate certificadoCliente;
	private SecretKey desKey;
	private final static String PADDING="AES/ECB/PKCS5Padding";
	
	private String algoritmos;


	public Cliente(String algs) {
		this.algoritmos = algs;
		
		try {
			socket = new Socket(HOST,  puerto);
			escritor = new PrintWriter( socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		} catch (Exception e) {
			System.err.println("Exception: " + e.getMessage()); System.exit(1);
		}
	
	}

	public void run() {
		
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		String fromServer = "";
		String fromServerCompuesto[];
		String fromUser = "";
		String coordenadas = "";
		byte[] myByte = null;

		try {
		// Paso 1
		System.out.println("Escriba el mensaje para enviar:"); 
		fromUser = stdIn.readLine(); 
		System.out.println("Mensaje ingresado: '" + fromUser + "'" ); 
		System.out.println("Escriba las coordenadas para enviar (ej: 41 24.2028, 2 10.4418):");
		coordenadas = stdIn.readLine();
		if(verificarCoordenadas(coordenadas)) {
			System.out.println("Coordenadas ingresadas: '" + coordenadas + "'" );
		}
		else {
			System.out.println("Las coordenadas ingresadas no son válidas. Cerrrando conexión.");
			cerrar();
			System.exit(0);
		}
		System.out.println(CLI+fromUser);
		escritor.println(fromUser);

		// Paso 2

		fromServer = lector.readLine();
		System.out.println(SERV+fromServer);
		if(!fromServer.equals(INICIO)) {
			System.out.println(ERROR + " " + CERRAR);
			cerrar();
		}

		// Paso 3
		
		System.out.println(CLI+algoritmos);
		escritor.println(algoritmos);

		// Paso 4
		fromServer = lector.readLine();
		System.out.println(SERV+fromServer);
		verificar(fromServer);

		// Paso 5
		fromUser = CERTIFICADO;
		escritor.println(fromUser);
		System.out.println(CLI+fromUser);

		// Paso 6
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
		keyPair = keyGen.generateKeyPair();

		Security.addProvider(new BouncyCastleProvider());
		keyGen.initialize(1024);
		X509Certificate certificadoServidor = generateV3Certificate(keyPair);

		try {
			myByte = certificadoServidor.getEncoded();
		} catch (CertificateEncodingException e) { 
			e.printStackTrace();
		}

		socket.getOutputStream().write(myByte);
		socket.getOutputStream().flush();


		// Paso 7
		fromServer = lector.readLine();
		System.out.println(SERV+fromServer);
		verificar(fromServer);

		// Paso 8
		fromServer = lector.readLine();
		System.out.println(SERV+fromServer);
		if(!fromServer.equals("CERTSRV")) {
			System.out.println(ERROR + " " + CERRAR);
			cerrar();
		}

		// Paso 9
		verificarCertificado();

		// Paso 10
		fromServer = lector.readLine();
		System.out.println(SERV + fromServer);

		boolean seguridad = false;

		if(fromServer.contains(":")) {
			seguridad = true;
		}

		if(seguridad) {
			
			fromServerCompuesto = fromServer.split(":");

			if(!fromServerCompuesto[0].equals(INICIO)) {
				System.out.println(ERROR + " " + CERRAR);
				cerrar();
			}
			
			System.out.println("Llave servidor" +fromServerCompuesto[1]);
			
			

		}
		else if(!seguridad) {	
			if(!fromServer.equals(INICIO)) {
				System.out.println(ERROR + " " + CERRAR);
				cerrar();
			}

			// Paso 11
			escritor.println(ACT1);
			System.out.println(CLI + ACT1);

			// Paso 12
			escritor.println(ACT2);
			System.out.println(CLI + ACT2);

		}

		// Paso 13
		fromServer = lector.readLine();
		System.out.println(SERV + fromServer);
		verificar(fromServer);
		
		} catch(Exception e) {
			try {
				cerrar();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}

	}

	public void cerrar() throws IOException {
		escritor.close();
		lector.close();
		// cierre el socket y la entrada estándar
		socket.close();
	}

	public void verificar(String mensaje) throws IOException {
		String[] mensajeC = mensaje.split(":");
		if(mensajeC[1].equals(ERROR)) {
			System.out.println(ERROR + " " + CERRAR);
			cerrar();
		}
	}


	//Generador de X509Certificate que necesita una llave por parámetro
	public static X509Certificate generateV3Certificate(KeyPair pair) throws Exception {
		X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		nameBuilder.addRDN(BCStyle.OU, "OU");
		nameBuilder.addRDN(BCStyle.O, "O");
		nameBuilder.addRDN(BCStyle.CN, "CN");
		String stringDate1 = "2016-10-01";
		String stringDate2 = "2020-12-20";
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
		Date notBefore = null;
		Date notAfter = null;
		try {
			notBefore = format.parse(stringDate1);
			notAfter = format.parse(stringDate2);
		}
		catch (ParseException e) {
			e.printStackTrace();
		}
		BigInteger serialNumber = new BigInteger(128, new Random());
		JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(nameBuilder.build(), serialNumber, notBefore, notAfter, nameBuilder.build(), pair.getPublic());
		X509Certificate certificate = null;
		try {
			ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(pair.getPrivate());
			certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));
		}
		catch (OperatorCreationException e) {
			e.printStackTrace();
		}
		catch (CertificateException e) {
			e.printStackTrace();
		}
		return certificate;
	}

	public void verificarCertificado() throws IOException, CertificateException
	{
		InputStream is = socket.getInputStream();
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		byte[] certificadoClienteBytes = new byte['ᎈ'];

		is.read(certificadoClienteBytes);
		InputStream inputStream = new ByteArrayInputStream(certificadoClienteBytes);

		try {
			certificadoCliente = ((X509Certificate)certFactory.generateCertificate(inputStream));
		} catch (CertificateException ce) {
			escritor.println(ERROR);
			System.out.println(CLI + ERROR);
			cerrar();

		}
		escritor.println(OK);
		System.out.println(CLI + OK);	
	}

	public boolean verificarCoordenadas(String coordenadas) {
		boolean correcto = false;

		if(coordenadas.contains(",")) {
			correcto = true;
		}

		return correcto;
	}

	public void descifrar(byte [] cipheredText) { try {
		Cipher cipher = Cipher.getInstance(PADDING); cipher.init(Cipher.DECRYPT_MODE, desKey);
		byte [] clearText = cipher.doFinal(cipheredText); String s3 = new String(clearText); System.out.println("clave original: " + s3);
	}
	catch (Exception e) {
		System.out.println("Excepcion: " + e.getMessage()); }
	}

	public static String toHexString(byte[] array) {
		return DatatypeConverter.printHexBinary(array);
	}

	public static byte[] toByteArray(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}

	public byte[] cifrar() { byte [] cipheredText;
	try {
		KeyGenerator keygen = KeyGenerator.getInstance(AES); desKey = keygen.generateKey();
		Cipher cipher = Cipher.getInstance(PADDING);
		BufferedReader stdIn = new BufferedReader(
				new InputStreamReader(System.in));
		String pwd = stdIn.readLine();
		byte [] clearText = pwd.getBytes();
		String s1 = new String (clearText); System.out.println("clave original: " + s1);
		cipher.init(Cipher.ENCRYPT_MODE, desKey); long startTime = System.nanoTime(); cipheredText = cipher.doFinal(clearText); long endTime = System.nanoTime();
		String s2 = new String (cipheredText); System.out.println("clave cifrada: " + s2); System.out.println("Tiempo: " + (endTime - startTime)); return cipheredText;
	}
	catch (Exception e) {
		System.out.println("Excepcion: " + e.getMessage());
		return null; }
	}

	private byte[] getKeyedDigest(byte[] buffer) { try {
		MessageDigest md5 = MessageDigest.getInstance("MD5"); md5.update(buffer);
		return md5.digest();
	} catch (Exception e) { return null;
	} }
	
	public static void main(String[] args) throws IOException { 
		File archivo = new File("./docs/Datos.txt");
		BufferedReader lect = new BufferedReader(new FileReader(archivo));
		String algoritmos = lect.readLine();
		lect.close();
		try {
			Cliente cliente = new Cliente(algoritmos);
			cliente.start();
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}

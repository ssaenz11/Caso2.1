package Cliente;
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
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
	// Constantes Socket
	public final static String HOST = "localhost";
	public final static int puerto = 5000;

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

	// Constantes de roles
	public final static String SERV = "SERVIDOR: ";
	public final static String CLI = "CLIENTE: ";

	//Atributos del socket
	private Socket socket = null; 
	private PrintWriter escritor = null; 
	private BufferedReader lector = null;

	// Atributos de certificados
	private X509Certificate certificadoCliente;
	private X509Certificate certificadoServidor;

	// Keypair
	private KeyPair keyPair;

	// Atributos auxiliares
	private String algoritmos;
	private String[] algs;
	private byte[] llaveCreada;
	private SecretKey llaveSimetrica;

	/**
	 * Constructor de la clase cliente
	 * @param algs Algoritmos a utilizar para el proceso
	 */
	public Cliente(String algs) {
		this.algoritmos = algs;
		this.algs = algoritmos.split(":");
		verificarAlgoritmos();

		try {
			socket = new Socket(HOST,  puerto);
			escritor = new PrintWriter( socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		} catch (Exception e) {
			System.err.println("Exception: " + e.getMessage()); System.exit(1);
		}

	}

	/**
	 * Verifica que los algoritmos a utilizar sean válidos
	 */
	public void verificarAlgoritmos() {
		if(algs.length != 4) {
			System.out.println("Debe ingresar 4 componentes en el archivo Datos.txt");
			System.exit(0);
		}

		String alg1 = algs[1];
		if(alg1.equals(AES) || alg1.equals(BLOWFISH)) {
			System.out.println("Algoritmo simétrico: " + alg1);
		}
		else {
			System.out.println("El algoritmo " + alg1 + " no es válido como simétrico.");
			System.exit(0);
		}

		String alg2 = algs[2];
		if(alg2.equals(RSA)) {
			System.out.println("Algoritmo asimétrico: " + alg2);
		}
		else {
			System.out.println("El algoritmo " + alg2 + " no es válido como asimétrico.");
			System.exit(0);
		}

		String alg3 = algs[3];
		if(alg3.equals(HMACMD5) || alg3.equals(HMACSHA1) || alg3.equals(HMACSHA256)  ) {
			System.out.println("Algoritmo HMAC: " + alg3);
		}
		else {
			System.out.println("El algoritmo " + alg3 + " no es válido como HMAC.");
			System.exit(0);
			
		}
		
		System.out.println("Los algoritmos ingresados son válidos");


	}

	/**
	 * Termina todo el proceso
	 * @throws IOException Se lanza si existe un problema al cerrar los componentes
	 */
	public void cerrar() throws IOException {
		escritor.close();
		lector.close();
		// cierre el socket y la entrada estándar
		socket.close();
	}

	/**
	 * Verifica que no se haya producido un erro durante el proceso
	 * @param mensaje El mensaje que puede tener el error
	 * @throws IOException Se lanza si existe un problema al cerrar los componentes
	 */
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
			certificadoServidor = ((X509Certificate)certFactory.generateCertificate(inputStream));
		} catch (CertificateException ce) {
			escritor.println(ERROR);
			System.out.println(CLI + ERROR);
			cerrar();

		}
		escritor.println(OK);
		System.out.println(CLI + OK);	
	}

	/**
	 * Verifica que las coordenadas ingresdas sean válidas (Implementación futura)
	 * @param coordenadas Las coordenadas a verificar
	 * @return true - si son válidas, false - si no lo son
	 */
	public boolean verificarCoordenadas(String coordenadas) {
		boolean correcto = false;

		if(coordenadas.contains(",")) {
			correcto = true;
		}

		return correcto;
	}

	/**
	 * Descifra un mensaje
	 * @param mensaje El mensaje a descrifrar
	 * @param algoritmo El algoritmo que se usa para descrifrar el mensaje
	 * @param llave La llave requerida para descrifrar
	 * @return El mensaje descrifrado
	 * @throws IOException Se lanza si existe un problema al cerrar los componentes
	 */
	public byte[] descifrar(byte[] mensaje, String algoritmo, Key llave) throws IOException {
		byte[] descifrado = null;
		try {
			Cipher descifrador = Cipher.getInstance(algoritmo); 
			descifrador.init(Cipher.DECRYPT_MODE, llave);
			descifrado = descifrador.doFinal(mensaje);
		} catch (Exception e) {
			System.out.println(ERROR + ":DESCIFRANDO " + CERRAR);
			cerrar();
		}
		return descifrado;

	}

	/**
	 * Cifra un mensaje
	 * @param mensaje El mensaje a cifrar
	 * @param algoritmo El algoritmo para cifrar
	 * @param llave La llave requerida para cifrarlo
	 * @return El mensaje cifrado
	 * @throws IOException Se lanza si existe un problema al cerrar los componentes
	 */
	public byte[] cifrar(byte[] mensaje, String algoritmo, Key llave) throws IOException {
		byte[] cifrado = null;
		try {
			Cipher cifrador = Cipher.getInstance(algoritmo);
			cifrador.init(1, llave);
			cifrado = cifrador.doFinal(mensaje);
		} catch (Exception e) {
			System.out.println(ERROR + ":CIFRANDO " + CERRAR);
			cerrar();
		}

		return cifrado;
	}

	/**
	 * Genera el código de integridad para un mensaje seleccionado
	 * @param mensaje El mensaje a partir del cual se calcula la integridad
	 * @param algoritmo El algoritmo para calcular la integridad
	 * @param llave La llave requeridad para generar la integridad
	 * @return El código de integridad
	 * @throws IOException Se lanza si existe un problema al cerrar los componentes
	 */
	public byte[] generarIntegridad(byte[] mensaje, String algoritmo, Key llave) throws IOException {
		byte[] integridad = null;
		try {
			Mac generador = Mac.getInstance(algoritmo);
			generador.init(llave);
			integridad = generador.doFinal(mensaje);
		} catch (Exception e) {
			System.out.println(ERROR + ":GENERANDO_INTEGRIDAD " + CERRAR);
			cerrar();
		}

		return integridad;
	}

	/**
	 * Convierte un arreglo en un string hexadecimal
	 * @param mensajeArreglo
	 * @return
	 */
	public static String hexadecimal(byte[] mensajeArreglo) {
		return DatatypeConverter.printHexBinary(mensajeArreglo);
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
			certificadoCliente = generateV3Certificate(keyPair);

			try {
				myByte = certificadoCliente.getEncoded();
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

				llaveCreada = descifrar(DatatypeConverter.parseHexBinary(fromServerCompuesto[1]), algs[2], this.keyPair.getPrivate());
				llaveSimetrica = new SecretKeySpec(llaveCreada, 0, llaveCreada.length, algs[1]);
				System.out.println(CLI + "Llave simétrica obtenida");

				// Paso 11
				byte[] act1A = cifrar(coordenadas.getBytes(), algs[1], llaveSimetrica);
				String act1 = hexadecimal(act1A);
				escritor.println(ACT1 + ":" + act1);
				System.out.println(CLI + ACT1 + ":" + act1);

				// Paso 12
				byte[] integridad = generarIntegridad(coordenadas.getBytes(), algs[3], llaveSimetrica);
				byte[] act2A = cifrar(integridad, algs[2], certificadoServidor.getPublicKey());
				String act2 = hexadecimal(act2A);
				escritor.println(ACT2 + ":" + act2);
				System.out.println(CLI + ACT2 + ":" + act2);
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
			
			cerrar();

		} catch(Exception e) {
			try {
				e.printStackTrace();
				cerrar();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}

	}
	
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

package ManejadorCarga;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import Cliente.Cliente;
import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {


	/**
	 * Carga el generador de Servicios
	 */
	private LoadGenerator generator;

	private String algoritmos;

	public static int completadas = 0;

	public static long obtenerLlave = 0;

	public static long actualizacion = 0;
	

	/**
	 * Constructor del generador
	 */

	public Generator(String algs)
	{
		algoritmos = algs;
		Task work = createTask();
		int numberOfTask = 100;
		int gapBetweenTasks = 80;
		generator = new LoadGenerator("Cliente - Prueba de carga del servidor", numberOfTask, work, gapBetweenTasks);
		generator.generate();
	}

	/**
	 * Creador de un Task
	 */
	private Task createTask()
	{
		return new ClientServerTask(algoritmos, this);
	}

	/**
	 * Empieza la aplicación
	 */

	public static void main (String[] args)
	{
		File archivo = new File("./docs/Datos.txt");
		BufferedReader lect = null;
		String algoritmos = null;

		try {

			lect = new BufferedReader(new FileReader(archivo));
			algoritmos = lect.readLine();
			lect.close();


		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		@SuppressWarnings("unused")
		Generator gen = new Generator(algoritmos);

	}
	
	public synchronized void aumentar(long llave, long actualizar){
		obtenerLlave += llave;
		actualizacion += actualizar;
		completadas ++;
		
		System.out.println(obtenerLlave + "," + actualizar + "," + completadas);
	}


}
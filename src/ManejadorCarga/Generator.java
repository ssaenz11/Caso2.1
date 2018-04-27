package ManejadorCarga;
import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;
import uniandes.gload.examples.clientserver.generator.ClientServerTask;

public class Generator {


	/**
	 * Carga el generador de Servicios
	 */
	private LoadGenerator generator;

	/**
	 * Constructor del generador
	 */

	public Generator()
	{

		Task work = createTask();
		int numberOfTask = 100;
		int gapBetweenTasks = 1000;
		generator = new LoadGenerator("Cliente - Prueba de carga del servidor", numberOfTask, work, gapBetweenTasks);
		generator.generate();
	}

	/**
	 * Creador de un Task
	 */
	private Task createTask()
	{
		return new ClientServerTask();
	}

	/**
	 * Empieza la aplicación
	 */

	public static void main (String[] args)
	{
		@SuppressWarnings("unused")
		Generator gen = new Generator();

	}


}

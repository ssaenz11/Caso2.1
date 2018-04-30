package ManejadorCarga;


import Cliente.Cliente;
import Cliente.ClienteSS;
import uniandes.gload.core.Task;

public class ClientServerTask extends Task
{
	private String algoritmos;
	private Generator generator;

	public ClientServerTask(String algs, Generator gen) {
		// TODO Auto-generated constructor stub
		algoritmos = algs;
		generator = gen;
	}

	@Override
	public void fail() {
		System.out.println("Falla");
	}

	@Override
	public void success() {
		System.out.println("Exito");
	}

	@Override
	public void execute() {
		// TODO Auto-generated method stub

		Cliente cliente = new Cliente(algoritmos, generator);
		//ClienteSS clienteSS = new ClienteSS(algoritmos, generator);
		cliente.start();
	}

}

package ManejadorCarga;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import Cliente.Cliente;
import Cliente.ClienteSS;
import uniandes.gload.core.Task;

public class ClientServerTask extends Task
{
	
	public Generator generator;
	
	public String algoritmos;

	public ClientServerTask(Generator gen, String algs) {
		generator = gen;
		algoritmos = algs;	
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
		//ClienteSS clienteSS = new ClienteSS(algoritmos);
		cliente.start();

	}

}
package ManejadorCarga;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import Cliente.Cliente;
import uniandes.gload.core.Task;

public class ClientServerTask extends Task
{


	@Override
	public void fail() {
		System.out.println("falla");
	}

	@Override
	public void success() {
		// TODO Auto-generated method stub

	}

	@Override
	public void execute() {
		// TODO Auto-generated method stub

		File archivo = new File("./docs/Datos.txt");
		BufferedReader lect = null;
		String algoritmos = null;

		try {
			
			lect = new BufferedReader(new FileReader(archivo));
			algoritmos = lect.readLine();
			lect.close();
			Cliente cliente = new Cliente(algoritmos);
			cliente.start();
			
			
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}







	}

}

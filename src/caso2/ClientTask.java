package caso2;

import uniandes.gload.core.Task;

public class ClientTask extends Task{

	private static int fallas = 0;

	@Override
	public void fail() {
		System.out.println(Task.MENSAJE_FAIL);
		setFallas(getFallas() + 1);
	}

	@Override
	public void success() {
		System.out.println(Task.OK_MESSAGE);
	}

	@Override
	public void execute() {
		try {
		//	Cliente cliente = new Cliente(Cliente.SEGURIDAD);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static int getFallas() {
		return fallas;
	}

	public synchronized static void setFallas(int fallas) {
		ClientTask.fallas = fallas;
	}

}

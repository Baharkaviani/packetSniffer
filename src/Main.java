import java.util.Scanner;

public class Main extends Thread {
    private Scanner scanner = new Scanner(System.in);
    private static PackageCapture packageCapture = null;
    private static FileHandling fileHandling = null;

    public static void main(String[] args) {
        Main thread = new Main();
        fileHandling = new FileHandling();
        packageCapture = new PackageCapture(fileHandling);
        thread.start();
        packageCapture.start();
    }

    public void run() {
        if (scanner.hasNext()){
            packageCapture.stopCapture();
        }
    }
}
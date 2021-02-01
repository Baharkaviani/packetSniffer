import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 *
 */
class FileHandling {
    private File resFile = null;
    private BufferedWriter writer = null;

    /**
     *
     */
    FileHandling() {
        try {
            resFile = new File("captureFile.txt");

            if (resFile.createNewFile()) {
                System.out.println("File created: " + resFile.getName());
            } else {
                System.out.println("File already exists.");
            }

            // create a FileWriter Object and open given file in append mode.
            writer = new BufferedWriter(new FileWriter(resFile, true));

        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    /**
     *
     */
    void writeToFile(String str) {
        try {
            // Writes the content to the file
            writer.write(str + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    void closeFile() throws IOException {
        if (writer != null) {
            writer.close();
        }
    }
}
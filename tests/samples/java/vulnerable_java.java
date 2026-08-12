import java.sql.*;
import java.io.*;

public class VulnerableService {

    private static final String DB_PASSWORD = "AdminPassword456!";

    public void executeQuery(Connection conn, String userInput) throws Exception {
        // SQL Injection
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");

        // Command Injection
        Runtime.getRuntime().exec("ping -c 1 " + userInput);

        // Unsafe Deserialization (ObjectInputStream + readObject on same line)
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("input.ser"));
        Object obj = ois.readObject();

        // Console debug statement
        System.out.println("User input processed: " + userInput);
    }
}

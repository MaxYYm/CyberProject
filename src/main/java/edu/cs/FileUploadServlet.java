package edu.cs;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.Scanner;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;


@WebServlet("/FileUploadServlet")
@MultipartConfig(fileSizeThreshold = 1024 * 1024 * 10,  // 10 MB
                 maxFileSize = 1024 * 1024 * 50,        // 50 MB
                 maxRequestSize = 1024 * 1024 * 100)    // 100 MB
public class FileUploadServlet extends HttpServlet {

    private static final long serialVersionUID = 205242440643911308L;
    private static final String UPLOAD_DIR = "C:/ServerStorage/uploads"; // Absolute path outside web root

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Ensure the directory exists
        File fileSaveDir = new File(UPLOAD_DIR);
        if (!fileSaveDir.exists()) {
            fileSaveDir.mkdirs(); // Create directory if it doesn't exist
        }
    
        String fileName = "";
        for (Part part : request.getParts()) {
            fileName = getFileName(part);
    
            // Sanitize the file name
            fileName = sanitizeFileName(fileName);
    
            // Securely resolve the file path
            File secureFile = new File(fileSaveDir, fileName);
    
            // Validate path safety
            if (!secureFile.getCanonicalPath().startsWith(fileSaveDir.getCanonicalPath())) {
                throw new SecurityException("Invalid file path detected: " + fileName);
            }
    
            // Write the file
            part.write(secureFile.getPath());
        }
    
        // Initialize response message
        StringBuilder responseMessage = new StringBuilder();
    
        // Read the uploaded file, limiting to 1000 lines
        try (Scanner scanner = new Scanner(new File(UPLOAD_DIR + File.separator + fileName))) {
            StringBuilder content = new StringBuilder();
            int lineCount = 0;
    
            while (scanner.hasNextLine()) {
                if (lineCount >= 1000) {
                    responseMessage.append("Error: File exceeds the maximum limit of 1000 lines.");
                    writeToResponse(response, responseMessage.toString());
                    return;
                }
                content.append(scanner.nextLine()).append(System.lineSeparator());
                lineCount++;
            }
    
            // Escape content to prevent XSS
            String escapedContent = escapeHtml(content.toString());
            responseMessage.append("File uploaded successfully! Content: ").append(escapedContent);
    
            // Save file data to the database
            try (Connection conn = connectToRemoteDB()) {
                if (conn != null) {
                    saveFileDataToDB(conn, fileName, content.toString());
                    responseMessage.append(" File data saved to the database.");
                } else {
                    responseMessage.append(" Failed to connect to the database.");
                }
            } catch (SQLException e) {
                e.printStackTrace();
                responseMessage.append(" Error saving data to the database: ").append(e.getMessage());
            }
    
        } catch (IOException e) {
            responseMessage.append("Error reading file: ").append(e.getMessage());
        }
    
        // Send response
        writeToResponse(response, responseMessage.toString());
    }
    

    private Connection connectToRemoteDB() throws SQLException {
        String url = "jdbc:mysql://localhost:3306/db_repo"; 
        String username = "db_user";
        String password = "pass";

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            return DriverManager.getConnection(url, username, password);
        } catch (ClassNotFoundException e) {
            throw new SQLException("Database driver not found", e);
        }
    }

    private void saveFileDataToDB(Connection conn, String fileName, String content) throws SQLException {
        String insertSQL = "INSERT INTO uploaded_files (file_name, file_content) VALUES (?, ?)";
        try (PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {
            pstmt.setString(1, fileName);
            pstmt.setString(2, content);
            pstmt.executeUpdate();
        }
    }

    private String getFileName(Part part) {
        String contentDisp = part.getHeader("content-disposition");
        String[] tokens = contentDisp.split(";");
        for (String token : tokens) {
            if (token.trim().startsWith("filename")) {
                return token.substring(token.indexOf("=") + 2, token.length() - 1);
            }
        }
        return "";
    }

    private String sanitizeFileName(String fileName) {
        // Allow only alphanumeric, period, hyphen, and underscore in the file name to prevent directory traversal
        fileName = fileName.replaceAll("[^a-zA-Z0-9\\.\\-_]", "_");
        return fileName;
    }

    private void writeToResponse(HttpServletResponse resp, String results) throws IOException {
        resp.setContentType("text/plain");
        try (PrintWriter writer = resp.getWriter()) {
            writer.write(results);
            writer.flush();
        }
    }

    // Manual HTML escaping method
    private String escapeHtml(String content) {
        if (content == null) {
            return null;
        }
        
        content = content.replace("&", "&amp;");
        content = content.replace("<", "&lt;");
        content = content.replace(">", "&gt;");
        content = content.replace("\"", "&quot;");
        content = content.replace("'", "&apos;");
        
        return content;
    }
}

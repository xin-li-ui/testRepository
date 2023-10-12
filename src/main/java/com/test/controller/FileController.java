package com.test.controller;

import com.test.file.FileUtils;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * @author xin.li
 * @since 2022/12/28 17:08:00
 */
@RestController
@RequestMapping
public class FileController {

    @GetMapping("/download")
    public void downloadPDF(HttpServletRequest request, HttpServletResponse response) throws IOException {

        // 源文件
        String path1 = request.getSession().getServletContext().getRealPath("/pdf/uid_recovery_code.pdf");
        System.out.println(path1);
        FileUtils.generatePdf(path1);

        // 加密文件
        String path2 = request.getSession().getServletContext().getRealPath("/pdf/uid_recovery_code_encrypt.pdf");
        String pwd = "123";
        FileUtils.encryptPdf(path1, path2, pwd);


        // 输出流
        String fileName = "uid_recovery_code.pdf";
        response.reset();
        FileUtils.setAttachmentResponseHeader(response, fileName);
        response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE + "; charset=UTF-8");

        FileInputStream fileInputStream = new FileInputStream(path2);
        ServletOutputStream outputStream = response.getOutputStream();
        byte[] b = new byte[128];
        int len;
        while ((len = fileInputStream.read(b)) > 0){
            outputStream.write(b, 0, len);
        }
        fileInputStream.close();
        outputStream.close();

        // 删除文件
        Files.deleteIfExists(Paths.get(path1));
        Files.deleteIfExists(Paths.get(path2));
    }


}

package com.test.file;

import com.itextpdf.commons.utils.DateTimeUtil;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.Style;
import com.itextpdf.layout.borders.Border;
import com.itextpdf.layout.borders.SolidBorder;
import com.itextpdf.layout.element.*;
import com.itextpdf.layout.properties.BorderRadius;
import com.itextpdf.layout.properties.HorizontalAlignment;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.VerticalAlignment;
import com.test.controller.FileController;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Objects;

/**
 * @author xin.li@ui.com
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class FileUtils {

    public static void generatePdf(String path1) throws FileNotFoundException {
        // 源文件
        File file1 = new File(path1);
        file1.getParentFile().mkdirs();
        PdfDocument pdfDoc = new PdfDocument(new PdfWriter(path1));
        Document doc = new Document(pdfDoc);
        doc.setMargins(50, 80, 80, 60);
        doc.setFontSize(11);
        doc.setCharacterSpacing(0.1f);

        // icon
        Div div1 = new Div();
        Image uidIcon = new Image(ImageDataFactory.create(Objects.requireNonNull(FileController.class.getClassLoader().getResource("static/uid.png")))).setHeight(20);
        String date = DateTimeUtil.format(new Date(), "yyyy/MM/dd HH:mm");
        Table table1 = new Table(2).useAllAvailableWidth();
        table1.addCell(new Cell()
                .add(uidIcon)
                .addStyle(new Style().setBorder(Border.NO_BORDER).setVerticalAlignment(VerticalAlignment.MIDDLE)));
        table1.addCell(new Cell()
                .add(new Paragraph(date).addStyle(new Style()
                        .setFontColor(new DeviceRgb(128, 128, 128))
                        .setTextAlignment(TextAlignment.RIGHT)
                        .setVerticalAlignment(VerticalAlignment.MIDDLE)))
                .addStyle(new Style().setBorder(Border.NO_BORDER).setVerticalAlignment(VerticalAlignment.MIDDLE)));

        div1.add(table1);
        doc.add(div1);

        // recovery code
        Div div2 = new Div();
        Paragraph p2 = new Paragraph()
                .setHeight(50)
                .setFontSize(18)
                .setVerticalAlignment(VerticalAlignment.MIDDLE);
        p2.add(new Text("Recovery Code").setBold());
        div2.add(p2);
        doc.add(div2);

        // explain
        Div div3 = new Div();
        Paragraph p3 = new Paragraph()
                .setHorizontalAlignment(HorizontalAlignment.CENTER)
                .setMarginBottom(10);
        p3.add(new Text("If your account is locked or you have forgotten your password or MFA, you can use this recovery code to regain access to your account."));
        div3.add(p3);
        doc.add(div3);

        // table
        Div div4 = new Div();
        Paragraph p4 = new Paragraph()
                .setBorder(new SolidBorder(new DeviceRgb(192, 192, 192), 1))
                .setBorderRadius(new BorderRadius(10))
                .setPaddings(15, 10, 15, 10)
                .setMarginTop(8)
                .setMarginBottom(8);
        Table table2 = new Table(2).useAllAvailableWidth();
        table2.addCell(new Cell()
                .add(new Paragraph("Workspace Domain:"))
                .addStyle(new Style().setBorder(Border.NO_BORDER).setVerticalAlignment(VerticalAlignment.MIDDLE)));
        table2.addCell(new Cell()
                .add(new Paragraph("uim3.ui.com").setFontColor(new DeviceRgb(0, 111, 255)))
                .addStyle(new Style().setBorder(Border.NO_BORDER).setVerticalAlignment(VerticalAlignment.MIDDLE)));
        table2.startNewRow();
        table2.addCell(new Cell()
                .add(new Paragraph("Account Email:"))
                .addStyle(new Style().setPaddingTop(10).setPaddingBottom(10).setBorder(Border.NO_BORDER).setVerticalAlignment(VerticalAlignment.MIDDLE)));
        table2.addCell(new Cell()
                .add(new Paragraph("xin****@ui.com"))
                .addStyle(new Style().setPaddingTop(10).setPaddingBottom(10).setBorder(Border.NO_BORDER).setVerticalAlignment(VerticalAlignment.MIDDLE)));
        table2.startNewRow();
        table2.addCell(new Cell()
                .add(new Paragraph("Recovery Code:"))
                .addStyle(new Style().setBorder(Border.NO_BORDER).setVerticalAlignment(VerticalAlignment.MIDDLE)));
        table2.addCell(new Cell()
                .add(new Paragraph("7ULIS-HEM2I-UR5ZQ-K3P76-HHNBM").setBold())
                .addStyle(new Style().setBorder(Border.NO_BORDER).setVerticalAlignment(VerticalAlignment.MIDDLE)));
        p4.add(table2);
        div4.add(p4);
        doc.add(div4);


        // footer
        Div div5 = new Div();
        Paragraph p5 = new Paragraph()
                .setHorizontalAlignment(HorizontalAlignment.CENTER)
                .setMarginTop(10);
        p5.add(new Text("This recovery code will no longer be valid once it has been used. \n" +
                "If you have any questions, feel free to contact us at "));
        p5.add(new Text("uid.support@ui.com").setFontColor(new DeviceRgb(0, 111, 255)));
        p5.add(new Text("."));
        div5.add(p5);
        doc.add(div5);

        doc.close();
    }

    public static void encryptPdf(String resourcePath, String targetPath, String password) throws IOException {
        PdfDocument pdfDoc = new PdfDocument(
                new PdfReader(resourcePath),
                new PdfWriter(targetPath, new WriterProperties().setStandardEncryption(
                        password.getBytes(),
                        password.getBytes(),
                        EncryptionConstants.ALLOW_PRINTING,
                        EncryptionConstants.ENCRYPTION_AES_128))
        );
        pdfDoc.close();
    }

    /**
     * 下载文件名重新编码
     *
     * @param response     响应对象
     * @param realFileName 真实文件名
     */
    public static void setAttachmentResponseHeader(HttpServletResponse response, String realFileName) throws UnsupportedEncodingException {
        String percentEncodedFileName = percentEncode(realFileName);

        StringBuilder contentDispositionValue = new StringBuilder();
        contentDispositionValue.append("attachment; filename=")
            .append(percentEncodedFileName)
            .append(";")
            .append("filename*=")
            .append("utf-8''")
            .append(percentEncodedFileName);

        response.addHeader("Access-Control-Expose-Headers", "Content-Disposition,download-filename");
        response.setHeader("Content-disposition", contentDispositionValue.toString());
        response.setHeader("download-filename", percentEncodedFileName);
    }

    /**
     * 百分号编码工具方法
     *
     * @param s 需要百分号编码的字符串
     * @return 百分号编码后的字符串
     */
    public static String percentEncode(String s) throws UnsupportedEncodingException {
        String encode = URLEncoder.encode(s, StandardCharsets.UTF_8.toString());
        return encode.replaceAll("\\+", "%20");
    }
}
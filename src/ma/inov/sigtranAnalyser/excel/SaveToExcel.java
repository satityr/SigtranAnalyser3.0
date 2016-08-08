/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ma.inov.sigtranAnalyser.excel;

import static ma.inov.sigtranAnalyser.mainClasses.Main.jProgressBar1;
import static ma.inov.sigtranAnalyser.mainClasses.Main.jTable1;
import java.io.File;
import javax.swing.JOptionPane;
import jxl.Workbook;
import jxl.write.Label;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;

/**
 *
 * @author BilGwiN
 */
public class SaveToExcel {

    int a = 0; //rows offset in jTable.
    int b = 1; // to give a sheet numbre with name and location.

    WritableSheet sheet;
    Label label;

    public void SaveExcel() {

        try {

            WritableWorkbook workbook = Workbook.createWorkbook(new File("File.xls"));

            for (int j = 0; j < jTable1.getRowCount(); j++) {
                
                a++;
  //-------------| create new sheet every 60000 rows |---------------------- 
  
                if (j % 60000 == 0) {
                    a = 0;
                    sheet = workbook.createSheet("Sheet" + (b++) + "", b - 1);

                    String Label[] = new String[10];
                    Label[0] = "Adaptation";
                    Label[1] = "Layer";
                    Label[2] = "OPC";
                    Label[3] = "DPC";
                    Label[4] = "NI";
                    Label[5] = "Source IP Address";
                    Label[6] = "Source Port";
                    Label[7] = "Destination IP";
                    Label[8] = "Destination Port";
                    Label[9] = "VLAN";

                    for (int x = 0; x < Label.length; x++) {
                        label = new Label(x, 0, Label[x]);
                        sheet.addCell(label);
                    }
                }
 //-------------| Loop for populate Columns of excel from jTable |-----------
 
                for (int i = 0; i < jTable1.getColumnCount(); i++) {

                    label = new Label(i, (a + 1), jTable1.getModel().getValueAt(j, i).toString());
                    sheet.addCell(label);

                }

            }

            workbook.write();
            workbook.close();

            jProgressBar1.setValue(0);

            JOptionPane.showMessageDialog(null, "Done .\n You can find the file in your application folder");

        } catch (Exception ex) {

            JOptionPane.showMessageDialog(null, ex);

        }
    }

}

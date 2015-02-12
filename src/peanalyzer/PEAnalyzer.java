package peanalyzer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;


public class PEAnalyzer extends JFrame {


    public PEAnalyzer() {

        super("PE Analyzer");

        setSize(400, 200);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        setResizable(false);

        initFileDialog();


        pack();
        setVisible(true);
    }

    private void initFileDialog() {
        JFileChooser fileChooser = new JFileChooser(".");
        fileChooser.setDialogTitle("Choose a file");
        //fileChooser.setDialogType(JFileChooser.FILES_ONLY);
        fileChooser.setDialogType(JFileChooser.OPEN_DIALOG);
        //fileChooser.setControlButtonsAreShown(false);

        fileChooser.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = (JFileChooser) e.getSource();
                if (JFileChooser.APPROVE_SELECTION.equals(e.getActionCommand())) {


                    chooser.setVisible(false);

                    File selectedFile = chooser.getSelectedFile();
                    processFile(selectedFile);


                    System.exit(0);

                } else if (JFileChooser.CANCEL_SELECTION.equals(e.getActionCommand())) {

                    dispose();
                    System.exit(0);
                }
            }
        });

        add(fileChooser, BorderLayout.CENTER);


    }

    private void processFile(File file) {
        try {
            displayFileName(file.getCanonicalPath());
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println(file.getParent());
        System.out.println(file.getName());


        PEFileDump fileDump = null;
        try {
            fileDump = PEDumper.processFile(file);
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println(fileDump.getCSV(null, null, null));


    }

    private void displayFileName(String fileName) {
        setLayout(new FlowLayout());
        JLabel label = new JLabel("Selected file: " + fileName, JLabel.CENTER);
        getContentPane().add(label);
    }

    public static void main(String[] args) {

        new PEAnalyzer();
    }
}

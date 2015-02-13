package peanalyzer;

import com.rapidminer.Process;
import com.rapidminer.RapidMiner;
import com.rapidminer.example.Attribute;
import com.rapidminer.example.Example;
import com.rapidminer.example.ExampleSet;
import com.rapidminer.operator.IOContainer;
import com.rapidminer.operator.Operator;
import com.rapidminer.operator.OperatorException;
import com.rapidminer.tools.XMLException;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.util.Iterator;

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
        fileChooser.setDialogType(JFileChooser.OPEN_DIALOG);

        fileChooser.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = (JFileChooser) e.getSource();
                if (JFileChooser.APPROVE_SELECTION.equals(e.getActionCommand())) {


                    chooser.setVisible(false);

                    File selectedFile = chooser.getSelectedFile();
                    processFile(selectedFile);

                } else if (JFileChooser.CANCEL_SELECTION.equals(e.getActionCommand())) {

                    dispose();
                    System.exit(0);
                }
            }
        });

        add(fileChooser, BorderLayout.CENTER);


    }

    private void processFile(File file) {
        String canonicalPath = null;
        try {
            canonicalPath = file.getCanonicalPath();
        } catch (IOException e) {
            e.printStackTrace();
        }
        displayFileName(file.getName());

        PEFileDump fileDump = null;
        try {
            fileDump = PEDumper.processFile(file);
        } catch (IOException e) {
            e.printStackTrace();
        }

        //noinspection ConstantConditions
        String fileDumpCSV = fileDump.getCSV(null, null, null);
        String csvFilePath = canonicalPath + ".csv";

        PrintWriter writer = null;
        try {
            writer = new PrintWriter(csvFilePath, "UTF-8");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        writer.print(fileDumpCSV);
        writer.close();

        String prediction = null;
        try {
            prediction = runRapidminer(csvFilePath);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (XMLException e) {
            e.printStackTrace();
        } catch (OperatorException e) {
            e.printStackTrace();
        }

        displayFilePrediction(prediction);

    }

    private void displayFileName(String fileName) {
        setLayout(new FlowLayout());
        JLabel label = new JLabel(fileName, JLabel.CENTER);
        getContentPane().add(label);
    }

    private void displayFilePrediction(String prediction) {
        setLayout(new FlowLayout());
        JLabel label = new JLabel(prediction, JLabel.CENTER);
        getContentPane().add(label);
    }


    private static String runRapidminer(String csvFilePath) throws IOException, XMLException, OperatorException {
        RapidMiner.setExecutionMode(RapidMiner.ExecutionMode.COMMAND_LINE);
        RapidMiner.init();

        File processFile = new File(new File("models/generalprocess").getAbsolutePath());
        Process pr = new Process(processFile);

        // System.out.println(pr.getAllOperatorNames());
        // [Process, Read Model, Read CSV, Apply Model]


        Operator readCSV = pr.getOperator("Read CSV");
        // System.out.println(readCSV.getParameters());
        // {csv_file=/Users/ashchogoleva/Desktop/query_bening.csv, column_separators=;, trim_lines=false, use_quotes=true, quotes_character=", escape_character=\, skip_comments=false, comment_characters=#, parse_numbers=true, decimal_character=., grouped_digits=false, grouping_character=,, date_format=, first_row_as_names=false, annotations=0␝Name, time_zone=SYSTEM, locale=English (United States), encoding=UTF-8, data_set_meta_data_information=, read_not_matching_values_as_missings=true, datamanagement=double_array}
        readCSV.setParameter("csv_file", csvFilePath);

        Operator readModel = pr.getOperator("Read Model");
        // System.out.println(readModel.getParameters());
        // {model_file=/Users/ashchogoleva/GraduationWork/rapidminer/models/k-NN-bin}

        //String modelName = "DesTreeFile";
        String modelName = "k-NN-bin";
        String modelFilePath = new File(new File("models/" + modelName).getAbsolutePath()).getCanonicalPath();
        readModel.setParameter("model_file", modelFilePath);

        IOContainer ioResult = pr.run();
        //System.out.println(ioResult.asList());

        String prediction = null;

        if (ioResult.getElementAt(0) instanceof ExampleSet) {
            ExampleSet resultSet = (ExampleSet) ioResult.getElementAt(0);
            Example example = resultSet.getExample(0);


            Iterator<Attribute> allAtts = example.getAttributes().allAttributes();
            while (allAtts.hasNext()) {
                Attribute a = allAtts.next();
                if (a.getName().equals("prediction(malware)")) {
                    prediction = example.getValueAsString(a);
                }
            }

        }

        return prediction;

    }


    public static void main(String[] args) {

        new PEAnalyzer();
    }
}

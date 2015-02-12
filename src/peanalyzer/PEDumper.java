package peanalyzer;

import com.googlecode.jcsv.writer.CSVEntryConverter;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.IOException;
import java.util.Map;

public class PEDumper implements CSVEntryConverter<PEFileDump> {

    public static final PEDumper INSTANCE = new PEDumper();

    public static void main(String[] args) {

        String result = PEUtils.executeCommand("pedump --format inspect --pe");

    }

    public static PEFileDump processFile(File file) throws IOException {

        PEFileDump fileDump = new PEFileDump();

        fileDump.filename = file.getName();
        fileDump.size = file.length();

        String filePath = file.getCanonicalPath();

        PEDumper.INSTANCE.extractPEData(filePath, fileDump);

        return fileDump;
    }

    private void extractPEData(String filepath, PEFileDump fileDump) {
        String dump = this.getDump(filepath, "--pe");
        dump = dump.replaceAll("=== PE Header ===", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::PE", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::IMAGE_FILE_HEADER", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::IMAGE_OPTIONAL_HEADER64", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::IMAGE_DATA_DIRECTORY", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::IMAGE_SECTION_HEADER", "");
        dump = dump.replaceAll("\\!binary", "");

        Yaml yaml = new Yaml();

        Map peHeader = (Map) yaml.load(dump);

        System.out.println(peHeader.keySet());

        Map image_optional_header = (Map) peHeader.get("image_optional_header");
        fileDump.sizeOfInitializedData = (Integer) image_optional_header.get("SizeOfInitializedData");

        Map image_file_header = (Map) peHeader.get("image_file_header");
        fileDump.numberOfSymbols = (Integer) image_file_header.get("NumberOfSymbols");
    }

    private String getDump(String filepath, String header) {

        String command = "pedump --format yaml";
        command += " " + header;
        command += " " + filepath;

        System.out.println(command);
        //noinspection UnnecessaryLocalVariable
        String result = PEUtils.executeCommand(command);


        return result;
    }

    @Override
    public String[] convertEntry(PEFileDump peFileDump) {
        String[] columns = new String[3];


        return columns;
    }
}



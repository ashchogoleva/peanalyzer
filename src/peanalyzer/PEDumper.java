package peanalyzer;

import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.IOException;
import java.util.Map;

public class PEDumper {

    public static final PEDumper INSTANCE = new PEDumper();

    public static PEFileDump processFile(File file) throws IOException {

        PEFileDump fileDump = new PEFileDump();

        fileDump.filename = file.getName();
        fileDump.size = file.length();

        String filePath = file.getCanonicalPath();

        PEDumper.INSTANCE.extractMZData(filePath, fileDump);
        PEDumper.INSTANCE.extractPEData(filePath, fileDump);
        PEDumper.INSTANCE.extractDataDirectoryData(filePath, fileDump);

        return fileDump;
    }

    private void extractMZData(String filepath, PEFileDump fileDump) {
        String dump = this.getDump(filepath, "--mz");
        dump = dump.replaceAll("=== MZ Header ===", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::MZ", "");

        Yaml yaml = new Yaml();

        Map mzHeader = (Map) yaml.load(dump);

        fileDump.bytes_in_last_block = (Integer) mzHeader.get("bytes_in_last_block");
        fileDump.blocks_in_file = (Integer) mzHeader.get("blocks_in_file");
        fileDump.min_extra_paragraphs = (Integer) mzHeader.get("min_extra_paragraphs");
        fileDump.overlay_number = (Integer) mzHeader.get("overlay_number");

    }

    private void extractPEData(String filepath, PEFileDump fileDump) {
        String dump = this.getDump(filepath, "--pe");
        Yaml yaml = new Yaml();

        dump = dump.replaceAll("=== PE Header ===", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::PE", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::IMAGE_FILE_HEADER", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::IMAGE_OPTIONAL_HEADER64", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::IMAGE_DATA_DIRECTORY", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::IMAGE_SECTION_HEADER", "");
        dump = dump.replaceAll("\\!binary", "");


        Map peHeader = (Map) yaml.load(dump);

        Map image_optional_header = (Map) peHeader.get("image_optional_header");
        fileDump.sizeOfInitializedData = (Integer) image_optional_header.get("SizeOfInitializedData");

        Map image_file_header = (Map) peHeader.get("image_file_header");
        fileDump.numberOfSymbols = (Integer) image_file_header.get("NumberOfSymbols");
    }

    private void extractDataDirectoryData(String filepath, PEFileDump fileDump) {
        String dump = this.getDump(filepath, "--data-directory");
        dump = dump.replaceAll("=== DATA DIRECTORY ===", "");
        dump = dump.replaceAll("\\!ruby\\/struct:PEdump::IMAGE_DATA_DIRECTORY", "");
        System.out.println(dump);

        //Yaml yaml = new Yaml();

        //Map dataDirectory = (ArrayList) yaml.load(dump);


    }

    private String getDump(String filepath, String header) {

        String command = "pedump --format yaml";
        command += " " + header;
        command += " " + filepath;

        //System.out.println(command);

        //noinspection UnnecessaryLocalVariable
        String result = PEUtils.executeCommand(command);
        //System.out.println(result);


        return result;
    }

}



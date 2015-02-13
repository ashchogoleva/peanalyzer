package peanalyzer;

import java.lang.reflect.Field;

public class PEFileDump {


    public String filename;
    public String md5 = "";
    public long size;
    public String malware = null;
    public int bytes_in_last_block;
    public int blocks_in_file;
    public int min_extra_paragraphs;
    public int overlay_number;
    public int sizeOfInitializedData;
    public int numberOfSymbols;
    public int size_EXPORT;
    public int size_IAT;
    public int size_Bound_IAT;
    public int size_LOAD_CONFIG;
    public int size_BASERELOC;
    public int size_CLR_Header;

    public static final String[] attributes = {
            "filename",
            "md5",
            "size",
            "malware",
            "bytes_in_last_block",
            "blocks_in_file",
            "min_extra_paragraphs",
            "overlay_number",
            "sizeOfInitializedData",
            "numberOfSymbols",
            "size_EXPORT",
            "size_IAT",
            "size_Bound_IAT",
            "size_LOAD_CONFIG",
            "size_BASERELOC",
            "size_CLR_Header",
    };


    /**
     * @param delimeter delimeter
     * @param escape    escape
     * @param newLine   newLine
     * @return String
     */
    public String getCSV(String delimeter, String escape, String newLine) {
        if (delimeter == null) {
            delimeter = ";";
        }
        if (escape == null) {
            escape = "\"";
        }
        if (newLine == null) {
            newLine = "\r\n";
        }

        String header = "";
        String content = "";


        for (String attribute : attributes) {
            if (header.length() > 0) {
                header += delimeter;
            }
            header += escape + attribute + escape;

            if (content.length() > 0) {
                content += delimeter;
            }
            try {
                Field field = this.getClass().getField(attribute);

                if (field.get(this) != null) {

                    if (field.getType() == String.class) {

                        content += escape + field.get(this) + escape;

                    } else {
                        content += field.get(this);

                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        return header + newLine + content;
    }
}

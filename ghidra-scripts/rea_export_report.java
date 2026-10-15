//@category REA
//@description Export a structured JSON report about the program

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;

public class rea_export_report extends GhidraScript {

    private String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outDir = args.length > 0 ? args[0] : System.getProperty("java.io.tmpdir");
        new File(outDir).mkdirs();

        StringBuilder j = new StringBuilder();
        j.append("{\n");
        j.append("  \"name\": \"").append(esc(currentProgram.getName())).append("\",\n");
        j.append("  \"language\": \"").append(esc(currentProgram.getLanguageID().toString())).append("\",\n");
        j.append("  \"compiler\": \"").append(esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString())).append("\",\n");
        j.append("  \"image_base\": \"").append(currentProgram.getImageBase().toString()).append("\",\n");

        j.append("  \"segments\": [\n");
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (int i = 0; i < blocks.length; i++) {
            MemoryBlock b = blocks[i];
            j.append("    {\"name\": \"").append(esc(b.getName())).append("\",");
            j.append("\"start\": \"").append(b.getStart().toString()).append("\",");
            j.append("\"end\": \"").append(b.getEnd().toString()).append("\",");
            j.append("\"size\": ").append(b.getSize()).append(",");
            j.append("\"r\": ").append(b.isRead()).append(",");
            j.append("\"w\": ").append(b.isWrite()).append(",");
            j.append("\"x\": ").append(b.isExecute()).append(",");
            j.append("\"initialized\": ").append(b.isInitialized()).append("}");
            if (i < blocks.length - 1) j.append(",");
            j.append("\n");
        }
        j.append("  ],\n");

        int total = 0, external = 0, thunks = 0;
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            Function f = fit.next();
            total++;
            if (f.isExternal()) external++;
            if (f.isThunk()) thunks++;
        }
        j.append("  \"functions\": {\"total\": ").append(total)
         .append(", \"external\": ").append(external)
         .append(", \"thunks\": ").append(thunks).append("},\n");

        j.append("  \"symbols\": {\"total\": ")
         .append(currentProgram.getSymbolTable().getNumSymbols()).append("},\n");

        // Top strings
        List<String[]> strings = new ArrayList<>();
        DataIterator dit = currentProgram.getListing().getDefinedData(true);
        while (dit.hasNext()) {
            Data d = dit.next();
            DataType dt = d.getDataType();
            if (dt == null) continue;
            if (!dt.getName().equalsIgnoreCase("string")) continue;
            Object v = d.getValue();
            if (v == null) continue;
            String s = v.toString();
            if (s.length() > 3) {
                strings.add(new String[]{d.getAddress().toString(), s, Integer.toString(s.length())});
            }
        }
        strings.sort((a, b) -> Integer.compare(Integer.parseInt(b[2]), Integer.parseInt(a[2])));
        int lim = Math.min(300, strings.size());
        j.append("  \"top_strings\": [\n");
        for (int i = 0; i < lim; i++) {
            String[] s = strings.get(i);
            String val = s[1].length() > 300 ? s[1].substring(0, 300) : s[1];
            j.append("    {\"address\": \"").append(s[0]).append("\",");
            j.append("\"value\": \"").append(esc(val)).append("\",");
            j.append("\"length\": ").append(s[2]).append("}");
            if (i < lim - 1) j.append(",");
            j.append("\n");
        }
        j.append("  ]\n");
        j.append("}\n");

        String outPath = outDir + File.separator + "program_report.json";
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            pw.print(j.toString());
        }
        println("Wrote report to " + outPath);
    }
}
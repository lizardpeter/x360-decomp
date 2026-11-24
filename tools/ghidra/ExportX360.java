// Full per-function disassembly and pseudocode; report failures explicitly.
// @category Xbox360
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class ExportX360 extends HeadlessScript {
    BufferedWriter writer(Path p) throws IOException {
        return Files.newBufferedWriter(p,StandardCharsets.UTF_8);
    }
    String clean(String s){return s.replace('\t',' ').replace('\n',' ').replace('\r',' ');}
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2) throw new IllegalArgumentException("output directory and seed manifest required");
        Path out=Path.of(args[0]); Files.createDirectories(out);
        Path pseudo=out.resolve("pseudocode"); Files.createDirectories(pseudo);
        Path asm=out.resolve("disasm"); Files.createDirectories(asm);
        Set<String> expected=new HashSet<>();
        for(String line:Files.readAllLines(Path.of(args[1]))) {
            String[] r=line.split("\t"); if(r[0].equals("FUNCTION")) expected.add(r[1].toUpperCase());
        }
        Set<String> found=new HashSet<>();
        int total=0,success=0,failed=0,emptyAsm=0,withoutEntryInsn=0;
        long instructions=0;
        boolean timedOut=analysisTimeoutOccurred();
        DecompInterface decomp=new DecompInterface();
        decomp.toggleCCode(true); decomp.toggleSyntaxTree(false);
        if(!decomp.openProgram(currentProgram)) throw new IllegalStateException("decompiler initialization failed");
        try(BufferedWriter inventory=writer(out.resolve("functions.tsv"));
            BufferedWriter errors=writer(out.resolve("decompile_errors.tsv"))) {
            inventory.write("address\tname\tbody_bytes\tinstructions\tseeded\tdecompile_status\n");
            errors.write("address\terror\n");
            FunctionIterator functions=currentProgram.getFunctionManager().getFunctions(true);
            BufferedWriter pw=null,aw=null;
            try {
                while(functions.hasNext()) {
                    monitor.checkCancelled();
                    Function f=functions.next();
                    String addr=String.format("%08X",f.getEntryPoint().getOffset());
                    if(total%1000==0) {
                        if(pw!=null){pw.close();aw.close();}
                        String shard=String.format("%04d",total/1000);
                        pw=writer(pseudo.resolve(shard+".c.txt")); aw=writer(asm.resolve(shard+".asm.txt"));
                    }
                    boolean seeded=expected.contains(addr);if(seeded)found.add(addr);
                    aw.write("\n; FUNCTION "+addr+" "+clean(f.getName())+"\n");
                    InstructionIterator iter=currentProgram.getListing().getInstructions(f.getBody(),true);
                    int ins=0;
                    while(iter.hasNext()) {
                        Instruction inst=iter.next();aw.write(inst.getAddress()+"\t"+inst+"\n");ins++;
                    }
                    if(ins==0)emptyAsm++;
                    if(currentProgram.getListing().getInstructionAt(f.getEntryPoint())==null)withoutEntryInsn++;
                    instructions+=ins;
                    pw.write("\n/* FUNCTION "+addr+" "+clean(f.getName())+" */\n");
                    String state="ok";
                    try {
                        DecompileResults r=decomp.decompileFunction(f,20,monitor);
                        if(r.decompileCompleted() && r.getDecompiledFunction()!=null) {
                            pw.write(r.getDecompiledFunction().getC());pw.write("\n");success++;
                        } else {
                            state="failed"; failed++;String reason=clean(String.valueOf(r.getErrorMessage()));
                            errors.write(addr+"\t"+reason+"\n");pw.write("/* DECOMPILATION FAILED */\n");
                        }
                    } catch(Exception e) {
                        state="failed";failed++;errors.write(addr+"\t"+clean(String.valueOf(e))+"\n");
                        pw.write("/* DECOMPILATION FAILED */\n");
                    }
                    inventory.write(addr+"\t"+clean(f.getName())+"\t"+f.getBody().getNumAddresses()+"\t"+ins+"\t"+seeded+"\t"+state+"\n");
                    total++;
                    if(total%1000==0){inventory.flush();errors.flush();pw.flush();aw.flush();println("X360_EXPORT "+total+" ok="+success+" failed="+failed);}
                }
            } finally {if(pw!=null)pw.close();if(aw!=null)aw.close();}
        } finally {decomp.dispose();}
        try(BufferedWriter missing=writer(out.resolve("missing_seeds.tsv"))) {
            missing.write("address\n");
            for(String s:new TreeSet<>(expected)) if(!found.contains(s))missing.write(s+"\n");
        }
        String report="{\n"+
            "  \"analysis_timeout\": "+timedOut+",\n"+
            "  \"seed_count\": "+expected.size()+",\n"+
            "  \"seeds_found\": "+found.size()+",\n"+
            "  \"missing_seeds\": "+(expected.size()-found.size())+",\n"+
            "  \"functions\": "+total+",\n"+
            "  \"additional_functions\": "+(total-found.size())+",\n"+
            "  \"decompile_success\": "+success+",\n"+
            "  \"decompile_failed\": "+failed+",\n"+
            "  \"empty_disassembly\": "+emptyAsm+",\n"+
            "  \"missing_entry_instruction\": "+withoutEntryInsn+",\n"+
            "  \"instructions\": "+instructions+"\n}\n";
        Files.writeString(out.resolve("summary.json"),report);
        println("X360_EXPORT_RESULT "+report);
    }
}

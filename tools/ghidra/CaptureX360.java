// Capture the automatic analysis outcome before authoritative boundary repair.
// @category Xbox360
import java.nio.file.*;
import java.io.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.*;
public class CaptureX360 extends HeadlessScript {
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2) throw new IllegalArgumentException("receipt and candidate inventory required");
        int total=0;
        try(BufferedWriter out=Files.newBufferedWriter(Path.of(args[1]))) {
            out.write("address\tname\tbody_bytes\tentry_decoded\n");
            FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);
            while(it.hasNext()){
                monitor.checkCancelled();
                Function f=it.next();
                out.write(String.format("%08X\t%s\t%d\t%b\n",f.getEntryPoint().getOffset(),
                    f.getName().replace('\t',' '), f.getBody().getNumAddresses(),
                    currentProgram.getListing().getInstructionAt(f.getEntryPoint())!=null));
                total++;
            }
        }
        Files.writeString(Path.of(args[0]),"{\"analysis_timeout\":"+analysisTimeoutOccurred()+",\"auto_functions\":"+total+"}\n");
        println("X360_AUTO_CAPTURE "+total);
    }
}

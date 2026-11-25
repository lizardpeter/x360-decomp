// Verify original failing instruction encodings independently of auto-analysis.
// @category Xbox360
import java.nio.file.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
public class VerifyXenon extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1)throw new IllegalArgumentException("receipt path required");
        String[] mnemonic={"vspltw128","vor128","blr"};
        String[][] registers={{"vr37","vr1"},{"vr63","vr62"},{}};
        Address base=currentProgram.getMemory().getMinAddress();
        for(int i=0;i<mnemonic.length;i++){
            Address a=base.add(i*4);
            new DisassembleCommand(a,new AddressSet(a,a.add(3)),false).applyTo(currentProgram,monitor);
            Instruction ins=currentProgram.getListing().getInstructionAt(a);
            if(ins==null || !ins.getMnemonicString().equalsIgnoreCase(mnemonic[i]) || ins.getPcode().length==0)
                throw new IllegalStateException("unexpected decode/pcode at "+a+": "+ins);
            String line=ins.toString().toLowerCase();
            for(String reg:registers[i])
                if(!java.util.regex.Pattern.compile("\\b"+reg+"\\b").matcher(line).find())
                    throw new IllegalStateException("extended register mismatch: "+line+" expected "+reg);
            println("XENON_SMOKE "+a+" "+ins+" pcode="+ins.getPcode().length);
        }
        Files.writeString(Path.of(args[0]),"ok\n");
    }
}

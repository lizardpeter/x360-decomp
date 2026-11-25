// Restore exception-directory function ranges after heuristic auto-analysis.
// @category Xbox360
import java.io.*;
import java.nio.file.*;
import java.util.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class ReconcileX360 extends HeadlessScript {
    Address addr(String value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(value,16));
    }
    String hex(Address a){return String.format("%08X",a.getOffset());}
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2) throw new IllegalArgumentException("manifest and reconciliation directory required");
        Path output=Path.of(args[1]);Files.createDirectories(output);
        TreeMap<Address,AddressSet> seeds=new TreeMap<>();
        for(String line:Files.readAllLines(Path.of(args[0]))) {
            String[] r=line.split("\t");
            if(r[0].equals("FUNCTION")) {
                Address a=addr(r[1]);seeds.put(a,new AddressSet(a,a.add(Long.parseLong(r[2])-1)));
            }
        }
        FunctionManager fm=currentProgram.getFunctionManager();
        Listing listing=currentProgram.getListing();
        Memory mem=currentProgram.getMemory();
        // First collect conflicts, so no mutation occurs during function iteration.
        TreeSet<Address> conflicts=new TreeSet<>();
        int already=0, restored=0, bounded=0, rejected=0, invalid=0;
        for(Map.Entry<Address,AddressSet> e:seeds.entrySet()){
            monitor.checkCancelled();
            Iterator<Function> it=fm.getFunctionsOverlapping(e.getValue());
            while(it.hasNext()){
                Function f=it.next();
                if(!f.getEntryPoint().equals(e.getKey())) {
                    // Retain another authoritative entry, but trim its body below.
                    if(!seeds.containsKey(f.getEntryPoint())) conflicts.add(f.getEntryPoint());
                }
            }
        }
        try(BufferedWriter removed=Files.newBufferedWriter(output.resolve("conflicting_candidates.tsv"));
            BufferedWriter repairs=Files.newBufferedWriter(output.resolve("seed_reconciliation.tsv"))) {
            removed.write("address\tname\tbody_bytes\treason\n");
            repairs.write("address\toriginal_bytes\tstate\tentry_decoded\tdecoded_instruction_bytes\n");
            for(Address a:conflicts){
                Function f=fm.getFunctionAt(a);
                if(f!=null){
                    removed.write(hex(a)+"\t"+f.getName().replace('\t',' ')+"\t"+f.getBody().getNumAddresses()+"\toverlaps_authoritative_range\n");
                    fm.removeFunction(a);rejected++;
                }
            }
            // Contract surviving authoritative functions before restoring missing entries.
            // Intersection cannot overlap a different original exception-directory range.
            for(Map.Entry<Address,AddressSet> e:seeds.entrySet()){
                Function f=fm.getFunctionAt(e.getKey());
                if(f==null)continue;
                AddressSet clipped=f.getBody().intersect(e.getValue());
                if(!clipped.contains(e.getKey()))clipped.add(e.getKey());
                if(!clipped.equals(f.getBody())) {f.setBody(clipped);bounded++;}
            }
            for(Map.Entry<Address,AddressSet> e:seeds.entrySet()){
                monitor.checkCancelled();
                Address a=e.getKey();AddressSet range=e.getValue();
                Function f=fm.getFunctionAt(a);
                boolean existed=f!=null;
                MemoryBlock block=mem.getBlock(a);
                if(block==null || !block.isExecute() || !block.contains(range.getMaxAddress()))
                    throw new IllegalStateException("verified seed outside mapped executable section "+a);
                if(listing.getInstructionAt(a)==null){
                    // Clear heuristic data only at the verified entry, not arbitrary
                    // words throughout the function. Embedded data may be legitimate.
                    listing.clearCodeUnits(a,a.add(3),false);
                    new DisassembleCommand(a,range,true).applyTo(currentProgram,monitor);
                }
                if(listing.getInstructionAt(a)==null){
                    invalid++;
                    repairs.write(hex(a)+"\t"+range.getNumAddresses()+"\tentry_undecoded\tfalse\t0\n");
                    continue;
                }
                if(f==null) {
                    f=fm.createFunction("sub_"+hex(a),a,range,SourceType.IMPORTED);
                    if(f==null)throw new IllegalStateException("restore failed "+a);
                    restored++;
                }else{
                    already++;
                    if(!f.getBody().equals(range)){f.setBody(range);bounded++;}
                }
                long decoded=0;
                InstructionIterator instructions=listing.getInstructions(range,true);
                while(instructions.hasNext())decoded+=instructions.next().getLength();
                repairs.write(hex(a)+"\t"+range.getNumAddresses()+"\t"+(existed?"retained":"restored")+"\ttrue\t"+decoded+"\n");
            }
        }
        Files.writeString(output.resolve("reconcile_receipt.json"),"{\"seed_count\":"+seeds.size()+
            ",\"retained\":"+already+",\"restored\":"+restored+",\"undecoded_entries\":"+invalid+
            ",\"bounded_bodies\":"+bounded+",\"rejected_conflicts\":"+rejected+"}\n");
        println("X360_RECONCILE retained="+already+" restored="+restored+" undecoded="+invalid+" conflicts="+rejected);
    }
}

// Prepare verified loaded XEX sections and seed original exception-directory ranges.
// @category Xbox360
import java.nio.file.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class SeedX360 extends GhidraScript {
    Address address(String s) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(Long.parseUnsignedLong(s,16));
    }
    void splitAt(Memory mem,Address a) throws Exception {
        MemoryBlock b=mem.getBlock(a);
        if(b!=null && !b.getStart().equals(a)) mem.split(b,a);
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2) throw new IllegalArgumentException("seed manifest and completion receipt required");
        List<String> rows=Files.readAllLines(Path.of(args[0]));
        Memory mem=currentProgram.getMemory();
        String[] header=rows.get(0).split("\t");
        Address base=address(header[1]);
        // The raw loader maps bytes at loader-baseAddr, but the program property can remain zero.
        long imageSize=Long.parseLong(header[2]);
        if(!mem.getMinAddress().equals(base) || !mem.getMaxAddress().equals(base.add(imageSize-1)))
            throw new IllegalStateException("incorrect mapped image extent: "+mem.getMinAddress()+".."+mem.getMaxAddress());
        println("X360_MAPPED_BASE "+base+" program_property="+currentProgram.getImageBase());
        for(MemoryBlock b:mem.getBlocks()){b.setRead(true);b.setWrite(false);b.setExecute(false);}
        for(String row:rows) {
            String[] r=row.split("\t");
            if(!r[0].equals("SECTION")) continue;
            Address start=address(r[1]); long size=Long.parseLong(r[2]);
            Address end=start.add(size-1);
            splitAt(mem,start);
            if(end.compareTo(mem.getMaxAddress())<0) splitAt(mem,end.add(1));
            long flags=Long.parseUnsignedLong(r[3],16);
            for(MemoryBlock b:mem.getBlocks()) {
                if(b.getStart().compareTo(start)>=0 && b.getEnd().compareTo(end)<=0) {
                    b.setRead((flags&0x40000000L)!=0); b.setWrite((flags&0x80000000L)!=0);
                    b.setExecute((flags&0x20000000L)!=0);
                    b.setName(r[4]+"_"+b.getStart());
                }
            }
        }
        FunctionManager fm=currentProgram.getFunctionManager();
        int seeds=0,failed=0,labels=0;
        for(String row:rows) {
            monitor.checkCancelled();
            String[] r=row.split("\t"); if(r[0].equals("BASE")) continue;
            Address a=address(r[1]);
            if(r[0].equals("ENTRY")) {
                currentProgram.getSymbolTable().addExternalEntryPoint(a);
                continue;
            }
            if(r[0].equals("FUNCTION")) {
                seeds++;
                long size=Long.parseLong(r[2]); Address end=a.add(size-1);
                MemoryBlock b=mem.getBlock(a);
                if(b==null||!b.isExecute()||!b.contains(end)) {failed++;continue;}
                AddressSet body=new AddressSet(a,end);
                if(currentProgram.getListing().getInstructionAt(a)==null) {
                    DisassembleCommand cmd=new DisassembleCommand(a,body,true);
                    cmd.applyTo(currentProgram,monitor);
                }
                if(fm.getFunctionAt(a)==null) {
                    if(currentProgram.getListing().getInstructionAt(a)==null) {failed++;continue;}
                    try { fm.createFunction("sub_"+r[1],a,body,SourceType.IMPORTED); }
                    catch(Exception e){failed++;println("seed conflict "+a+": "+e.getMessage());}
                }
                if(seeds%2000==0) println("seeded "+seeds+" attempted; failures "+failed);
            } else if(r[0].equals("VALUE")||r[0].equals("THUNK")||r[0].equals("EXPORT")) {
                if(mem.contains(a)) {
                    currentProgram.getSymbolTable().createLabel(a,r[2],SourceType.IMPORTED);labels++;
                    if(r[0].equals("EXPORT") && mem.getBlock(a).isExecute())
                        currentProgram.getSymbolTable().addExternalEntryPoint(a);
                }
            }
        }
        int retained=0;
        for(String row:rows) {
            String[] r=row.split("\t");
            if(r[0].equals("FUNCTION") && fm.getFunctionAt(address(r[1]))!=null) retained++;
        }
        Files.writeString(Path.of(args[1]),"{\"attempted\":"+seeds+",\"failed\":"+failed+",\"retained\":"+retained+",\"labels\":"+labels+"}\n");
        println("X360_SEED_RESULT attempted="+seeds+" failed="+failed+" retained="+retained+" labels="+labels);
    }
}

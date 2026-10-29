// Print decompiled C for each function address given as a script argument.
// @category switch-recomp
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class Decompile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (String arg : getScriptArgs()) {
            Function f = getFunctionAt(toAddr(arg));
            if (f == null) {
                println("no function at " + arg);
                continue;
            }
            var result = decompiler.decompileFunction(f, 120, monitor);
            println("==== " + arg + "\n" + (result.decompileCompleted()
                    ? result.getDecompiledFunction().getC() : result.getErrorMessage()));
        }
    }
}

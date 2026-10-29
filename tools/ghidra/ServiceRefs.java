// For each service name given as a script argument, report the functions that
// reference its string and whether they are reachable from the entry point by
// direct calls (startup) or only through indirect calls (on demand).
// @category switch-recomp
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;

public class ServiceRefs extends GhidraScript {
    private final Map<Function, Integer> depth = new HashMap<>();
    private final Map<Function, Function> parent = new HashMap<>();

    @Override
    protected void run() throws Exception {
        Function entry = getFunctionAt(currentProgram.getImageBase());
        for (Address a : currentProgram.getSymbolTable().getExternalEntryPointIterator()) {
            Function f = getFunctionAt(a);
            if (f != null) entry = f;
        }
        // An NSO starts with a branch to its real start routine (crt0).
        var first = getInstructionAt(entry.getEntryPoint());
        if (first != null && first.getMnemonicString().equals("b") && first.getFlows().length == 1) {
            Function target = getFunctionAt(first.getFlows()[0]);
            if (target != null) entry = target;
        }
        reach(entry);
        println("entry " + entry.getEntryPoint() + ", " + depth.size() + " functions reachable by direct calls");

        Memory memory = currentProgram.getMemory();
        for (String name : getScriptArgs()) {
            byte[] pattern = (name + "\0").getBytes(StandardCharsets.US_ASCII);
            Set<Function> users = new LinkedHashSet<>();
            Address at = memory.getMinAddress();
            while ((at = memory.findBytes(at, pattern, null, true, monitor)) != null) {
                if (memory.getByte(at.subtract(1)) == 0) collectUsers(at, users, 2);
                at = at.add(1);
            }
            if (users.isEmpty()) {
                println(name + ": no code references");
                continue;
            }
            for (Function f : users) {
                Integer d = depth.get(f);
                println(name + ": " + f.getEntryPoint() + (d != null
                        ? " startup, depth " + d + ", path " + path(f)
                        : " on demand, roots " + roots(f)));
            }
        }
    }

    private void reach(Function entry) throws Exception {
        ArrayDeque<Function> queue = new ArrayDeque<>();
        depth.put(entry, 0);
        queue.add(entry);
        while (!queue.isEmpty()) {
            Function f = queue.poll();
            for (Function called : f.getCalledFunctions(monitor)) {
                // Step through thunks so a call via a thunk reaches its target.
                Function callee = called.isThunk() ? called.getThunkedFunction(true) : called;
                if (!depth.containsKey(callee)) {
                    depth.put(callee, depth.get(f) + 1);
                    parent.put(callee, f);
                    queue.add(callee);
                }
            }
        }
    }

    // Follow code references, and data references through one or two pointer hops.
    private void collectUsers(Address target, Set<Function> users, int hops) {
        for (Reference r : getReferencesTo(target)) {
            Function f = getFunctionContaining(r.getFromAddress());
            if (f != null) users.add(f);
            else if (hops > 0) collectUsers(r.getFromAddress(), users, hops - 1);
        }
    }

    private String path(Function f) {
        List<String> chain = new ArrayList<>();
        for (Function g = f; g != null; g = parent.get(g)) chain.add(0, g.getEntryPoint().toString());
        return String.join(" > ", chain);
    }

    // Callers-only ancestors with no direct callers: the indirect entry points.
    private String roots(Function f) throws Exception {
        Set<Function> seen = new HashSet<>();
        Set<String> found = new TreeSet<>();
        ArrayDeque<Function> queue = new ArrayDeque<>(List.of(f));
        while (!queue.isEmpty() && seen.size() < 2000) {
            Function g = queue.poll();
            if (!seen.add(g)) continue;
            Set<Function> callers = g.getCallingFunctions(monitor);
            if (callers.isEmpty()) found.add(g.getEntryPoint().toString());
            queue.addAll(callers);
        }
        return found.size() > 6 ? found.size() + " functions" : String.join(", ", found);
    }
}

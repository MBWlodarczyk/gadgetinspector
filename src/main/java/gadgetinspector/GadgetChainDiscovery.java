package gadgetinspector;

import gadgetinspector.config.GIConfig;
import gadgetinspector.config.JavaDeserializationConfig;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.DataLoader;
import gadgetinspector.data.GraphCall;
import gadgetinspector.data.InheritanceDeriver;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.data.Source;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import java.util.Optional;

public class GadgetChainDiscovery {

    private static final Logger LOGGER = LoggerFactory.getLogger(GadgetChainDiscovery.class);

    private final GIConfig config;

    public GadgetChainDiscovery(GIConfig config) {
        this.config = config;
    }

    public Set<GadgetChain> discover() throws Exception {
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        InheritanceMap inheritanceMap = InheritanceMap.load();
        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap = InheritanceDeriver.getAllMethodImplementations(
                inheritanceMap, methodMap);

        final ImplementationFinder implementationFinder = config.getImplementationFinder(
                methodMap, methodImplMap, inheritanceMap);

        try (Writer writer = Files.newBufferedWriter(Paths.get("methodimpl.dat"))) {
            for (Map.Entry<MethodReference.Handle, Set<MethodReference.Handle>> entry : methodImplMap.entrySet()) {
                writer.write(entry.getKey().getClassReference().getName());
                writer.write("\t");
                writer.write(entry.getKey().getName());
                writer.write("\t");
                writer.write(entry.getKey().getDesc());
                writer.write("\n");
                for (MethodReference.Handle method : entry.getValue()) {
                    writer.write("\t");
                    writer.write(method.getClassReference().getName());
                    writer.write("\t");
                    writer.write(method.getName());
                    writer.write("\t");
                    writer.write(method.getDesc());
                    writer.write("\n");
                }
            }
        }

        Map<MethodReference.Handle, Set<GraphCall>> graphCallMap = new HashMap<>();
        for (GraphCall graphCall : DataLoader.loadData(Paths.get("callgraph.dat"), new GraphCall.Factory())) {
            MethodReference.Handle caller = graphCall.getCallerMethod();
            if (!graphCallMap.containsKey(caller)) {
                Set<GraphCall> graphCalls = new HashSet<>();
                graphCalls.add(graphCall);
                graphCallMap.put(caller, graphCalls);
            } else {
                graphCallMap.get(caller).add(graphCall);
            }
        }

        Set<GadgetChainLink> exploredMethods = new HashSet<>();
        LinkedList<GadgetChain> methodsToExplore = new LinkedList<>();
        for (Source source : DataLoader.loadData(Paths.get("sources.dat"), new Source.Factory())) {
            GadgetChainLink srcLink = new GadgetChainLink(source.getSourceMethod(), source.getTaintedArgIndex());
            if (exploredMethods.contains(srcLink)) {
                continue;
            }
            methodsToExplore.add(new GadgetChain(Arrays.asList(srcLink)));
            exploredMethods.add(srcLink);
        }

        long iteration = 0;
        Set<GadgetChain> discoveredGadgets = new HashSet<>();
        while (methodsToExplore.size() > 0) {
            if ((iteration % 1000) == 0) {
                LOGGER.info("Iteration " + iteration + ", Search space: " + methodsToExplore.size());
            }
            iteration += 1;

            GadgetChain chain = methodsToExplore.pop();
            GadgetChainLink lastLink = chain.links.get(chain.links.size()-1);

            Set<GraphCall> methodCalls = graphCallMap.get(lastLink.method);
            if (methodCalls != null) {
                for (GraphCall graphCall : methodCalls) {
                    if (graphCall.getCallerArgIndex() != lastLink.taintedArgIndex) {
                        continue;
                    }

                    Set<MethodReference.Handle> allImpls = implementationFinder.getImplementations(graphCall.getTargetMethod());

                    for (MethodReference.Handle methodImpl : allImpls) {
                        GadgetChainLink newLink = new GadgetChainLink(methodImpl, graphCall.getTargetArgIndex());
                        if (exploredMethods.contains(newLink)) {
                            continue;
                        }

                        GadgetChain newChain = new GadgetChain(chain, newLink);
                        Optional<GadgetChain.Type> maybeType = isSink(methodImpl, graphCall.getTargetArgIndex(), inheritanceMap);
                        if (maybeType.isPresent()) {
                            newChain.type = maybeType.get();
                            discoveredGadgets.add(newChain);
                        } else {
                            methodsToExplore.add(newChain);
                            exploredMethods.add(newLink);
                        }
                    }
                }
            }
        }

        return discoveredGadgets;
    }

    /**
     * Represents a collection of methods in the JDK that we consider to be "interesting". If a gadget chain can
     * successfully exercise one of these, it could represent anything as mundade as causing the target to make a DNS
     * query to full blown RCE.
     * @param method
     * @param argIndex
     * @param inheritanceMap
     * @return
     */
    // TODO: Parameterize this as a configuration option
    private Optional<GadgetChain.Type> isSink(MethodReference.Handle method, int argIndex, InheritanceMap inheritanceMap) {
        if (method.getClassReference().getName().equals("java/io/FileInputStream")
                && method.getName().equals("<init>")) {
            return Optional.of(GadgetChain.Type.FILE);
        }
        if (method.getClassReference().getName().equals("java/io/FileOutputStream")
                && method.getName().equals("<init>")) {
            return Optional.of(GadgetChain.Type.FILE);
        }
        if (method.getClassReference().getName().equals("java/nio/file/Files")
            && (method.getName().equals("newInputStream")
                || method.getName().equals("newOutputStream")
                || method.getName().equals("newBufferedReader")
                || method.getName().equals("newBufferedWriter"))) {
            return Optional.of(GadgetChain.Type.FILE);
        }

        if (method.getClassReference().getName().equals("java/lang/Runtime")
                && method.getName().equals("exec")) {
            return Optional.of(GadgetChain.Type.RCE);
        }
        /*
        if (method.getClassReference().getName().equals("java/lang/Class")
                && method.getName().equals("forName")) {
            return Optional.of(GadgetChain.Type.UNKNOWN);
        }
        if (method.getClassReference().getName().equals("java/lang/Class")
                && method.getName().equals("getMethod")) {
            return Optional.of(GadgetChain.Type.UNKNOWN);
        }
        */
        // If we can invoke an arbitrary method, that's probably interesting (though this doesn't assert that we
        // can control its arguments). Conversely, if we can control the arguments to an invocation but not what
        // method is being invoked, we don't mark that as interesting.
        if (method.getClassReference().getName().equals("java/lang/reflect/Method")
                && method.getName().equals("invoke") && argIndex == 0) {
            return Optional.of(GadgetChain.Type.INVOKE);
        }
        if (method.getClassReference().getName().equals("java/net/URLClassLoader")
                && method.getName().equals("newInstance")) {
            return Optional.of(GadgetChain.Type.NET);
        }
        if (method.getClassReference().getName().equals("java/lang/System")
                && method.getName().equals("exit")) {
            return Optional.of(GadgetChain.Type.UNKNOWN);
        }
        if (method.getClassReference().getName().equals("java/lang/Shutdown")
                && method.getName().equals("exit")) {
            return Optional.of(GadgetChain.Type.UNKNOWN);
        }
        if (method.getClassReference().getName().equals("java/lang/Runtime")
                && method.getName().equals("exit")) {
            return Optional.of(GadgetChain.Type.UNKNOWN);
        }

        if (method.getClassReference().getName().equals("java/nio/file/Files")
                && method.getName().equals("newOutputStream")) {
            return Optional.of(GadgetChain.Type.FILE);
        }

        if (method.getClassReference().getName().equals("java/lang/ProcessBuilder")
                && method.getName().equals("<init>") && argIndex > 0) {
            return Optional.of(GadgetChain.Type.RCE);
        }

        if (inheritanceMap.isSubclassOf(method.getClassReference(), new ClassReference.Handle("java/lang/ClassLoader"))
                && method.getName().equals("<init>")) {
            return Optional.of(GadgetChain.Type.INVOKE);
        }

        if (method.getClassReference().getName().equals("java/net/URL") && method.getName().equals("openStream")) {
            return Optional.of(GadgetChain.Type.NET);
        }

        // Some groovy-specific sinks
        if (method.getClassReference().getName().equals("org/codehaus/groovy/runtime/InvokerHelper")
                && method.getName().equals("invokeMethod") && argIndex == 1) {
            return Optional.of(GadgetChain.Type.INVOKE);
        }

        if (inheritanceMap.isSubclassOf(method.getClassReference(), new ClassReference.Handle("groovy/lang/MetaClass"))
                && Arrays.asList("invokeMethod", "invokeConstructor", "invokeStaticMethod").contains(method.getName())) {
            return Optional.of(GadgetChain.Type.INVOKE);
        }

        // This jython-specific sink effectively results in RCE
        if (method.getClassReference().getName().equals("org/python/core/PyCode") && method.getName().equals("call")) {
            return Optional.of(GadgetChain.Type.RCE);
        }

        return Optional.ofNullable(null);
    }

    public static void main(String[] args) throws Exception {
        GadgetChainDiscovery gadgetChainDiscovery = new GadgetChainDiscovery(new JavaDeserializationConfig());
        gadgetChainDiscovery.discover();
    }
}

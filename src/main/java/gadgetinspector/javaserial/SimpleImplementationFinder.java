package gadgetinspector.javaserial;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.data.MethodReference;

import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class SimpleImplementationFinder implements ImplementationFinder  {

    private final SerializableDecider serializableDecider;
    private final Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap;
    private Map<MethodReference.Handle, Set<MethodReference.Handle>> getImplMemo;

    public SimpleImplementationFinder(SerializableDecider serializableDecider, Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap) {
        this.serializableDecider = serializableDecider;
        this.methodImplMap = methodImplMap;
        this.getImplMemo = new HashMap<>();
    }

    @Override
    public Set<MethodReference.Handle> getImplementations(MethodReference.Handle target) {
        Set<MethodReference.Handle> memoEntry = this.getImplMemo.get(target);
        if (memoEntry != null) {
           return memoEntry;
        }

        Set<MethodReference.Handle> allImpls = new HashSet<>();

        // Assume that the target method is always available, even if not serializable; the target may just be a local
        // instance rather than something an attacker can control.
        allImpls.add(target);

        Set<MethodReference.Handle> subClassImpls = methodImplMap.get(target);
        if (subClassImpls != null) {
            for (MethodReference.Handle subClassImpl : subClassImpls) {
                if (Boolean.TRUE.equals(serializableDecider.apply(subClassImpl.getClassReference()))) {
                    allImpls.add(subClassImpl);
                }
            }
        }

        this.getImplMemo.put(target, allImpls);
        return allImpls;
    }
}

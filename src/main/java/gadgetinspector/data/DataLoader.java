package gadgetinspector.data;

import com.google.common.io.Files;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class DataLoader {
    public static <T> List<T> loadData(Path filePath, DataFactory<T> factory) throws IOException {
        final List<String> lines = Files.readLines(filePath.toFile(), StandardCharsets.UTF_8);
        final List<T> values = new ArrayList<T>(lines.size());
        for (String line : lines) {
            values.add(factory.parse(line.split("\t", -1)));
        }
        return values;
    }

    public static <T> void saveData(Path filePath, DataFactory<T> factory, Collection<T> values) throws IOException {
        try (BufferedWriter writer = Files.newWriter(filePath.toFile(), StandardCharsets.UTF_8)) {
            for (T value : values) {
                final String[] fields = factory.serialize(value);
                if (fields == null) {
                    continue;
                }

                StringBuilder sb = new StringBuilder();
                for (String field : fields) {
                    if (field == null) {
                        sb.append("\t");
                    } else {
                        sb.append("\t").append(field);
                    }
                }
                writer.write(sb.substring(1));
                writer.write("\n");
            }
        }
    }

    public static Map<ClassReference.Handle, ClassReference> loadClasses() {
        try {
            Map<ClassReference.Handle, ClassReference> classMap = new ConcurrentHashMap<>();
            for (ClassReference classReference : loadData(Paths.get("classes.dat"), new ClassReference.Factory())) {
                classMap.put(classReference.getHandle(), classReference);
            }
            return classMap;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Map<MethodReference.Handle, MethodReference> loadMethods() {
        try {
            Map<MethodReference.Handle, MethodReference> methodMap = new ConcurrentHashMap<>();
            for (MethodReference methodReference : loadData(Paths.get("methods.dat"), new MethodReference.Factory())) {
                methodMap.put(methodReference.getHandle(), methodReference);
            }
            return methodMap;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

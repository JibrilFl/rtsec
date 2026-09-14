/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2026, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.utils;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Platform;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

abstract public class AbstractNativeLibrary<T extends Library> {
    protected abstract String getTempDirName();

    protected abstract Class<T> getInterfaceClass();

    protected abstract List<NativeComponent> getDependencyComponents();

    protected abstract NativeComponent getMainComponent();

    protected T load() {
        Path tempDir = Paths.get(System.getProperty("java.io.tmpdir"), getTempDirName());
        List<NativeComponent> dependencies = getDependencyComponents();
        NativeComponent mainComponent = getMainComponent();

        try {
            System.setProperty("jna.tmpdir", tempDir.toString());
            // Clear temporary directory before extracting native library to it as it can contain another one from
            // previous launch (JNA was unable to remove it for some reason).
            deleteDirectory(tempDir);
            Files.createDirectories(tempDir);

            for (NativeComponent dependency : dependencies) {
                NativeLibrary.getInstance(extractFromResourcePath(dependency.getPlatformSpecificName(), tempDir));
            }

            return Native.load(extractFromResourcePath(mainComponent.getPlatformSpecificName(), tempDir),
                    getInterfaceClass(), Collections.singletonMap(Library.OPTION_STRING_ENCODING, "UTF-8"));
        } catch (Exception e) {
            throw new RuntimeException("Native loading failed", e);
        }
    }

    /**
     * Attempts to extract a native library from the classpath resources and copies it to a specified target directory,
     * using platform-specific extraction logic.
     *
     * @param name          the name of the native library without platform-specific extensions.
     * @param targetBaseDir the target directory where the library will be extracted.
     * @return the absolute path to the extracted library file, suitable for loading with
     * {@link Native#load(String, Class)} or {@link Native#load(String, Class, Map)}.
     * @throws IOException        if the library cannot be read from resources or written to the target directory.
     * @throws URISyntaxException if the resource URI is malformed (macOS frameworks from JAR only).
     */
    private String extractFromResourcePath(String name, Path targetBaseDir) throws IOException, URISyntaxException {
        ClassLoader loader = ClassLoader.getSystemClassLoader();
        if (Platform.isMac()) {
            return extractFrameworkFromResourcePath(name, targetBaseDir, loader);
        }

        if (Platform.isWindows()) {
            return extractDllFromResourcePath(name, targetBaseDir, loader);
        }

        // Linux
        return Native.extractFromResourcePath(name, loader).getAbsolutePath();
    }

    /**
     * Attempts to extract a Windows .dll library from the classpath resources to a specified directory.
     * <p>
     * This method uses manual copying instead of JNA's {@link Native#extractFromResourcePath(String)} because
     * JNA modifies the library name during extraction. When a .dll has dependencies on other .dll files, name
     * preservation is critical to resolve those dependencies at runtime.
     *
     * @param name          the name of the library without platform-specific extension.
     * @param targetBaseDir the target directory where the .dll will be copied.
     * @param loader        the class loader to use for accessing the library from classpath resources.
     * @return the absolute path to the extracted .dll file, suitable for loading with
     * {@link Native#load(String, Class)} or {@link Native#load(String, Class, Map)}.
     * @throws IOException if the .dll cannot be read from resources or written to the target directory.
     */
    private String extractDllFromResourcePath(String name, Path targetBaseDir, ClassLoader loader) throws IOException {
        String libraryName = System.mapLibraryName(name);
        String resourcePath = Platform.RESOURCE_PREFIX + "/" + libraryName;
        Path targetFile = targetBaseDir.resolve(libraryName);

        try (InputStream in = loader.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new FileNotFoundException(".dll library not found in classpath: " + resourcePath);
            }

            Files.copy(in, targetFile, StandardCopyOption.REPLACE_EXISTING);
        }

        return targetFile.toAbsolutePath().toString();
    }

    /**
     * Attempts to extract a macOS .framework bundle from the classpath resources to a specified directory.
     * <p>
     * This method handles framework extraction from both JAR files and resource directories. A framework bundle
     * on macOS contains the library executable, headers, and resources organized in a specific directory structure.
     * This method copies the entire framework structure while locating the main executable file (matching the
     * framework name) for use with JNA.
     * <p>
     * The framework resources are expected to be located in a "darwin" resource directory.
     *
     * @param name          the name of the .framework bundle (without the .framework extension)
     * @param targetBaseDir the target directory where the framework bundle will be copied.
     * @param loader        the class loader to use for accessing the framework from classpath resources.
     * @return the absolute path to the main executable file within the extracted framework, suitable for loading with
     * {@link Native#load(String, Class)} or {@link Native#load(String, Class, Map)}.
     * @throws IOException        if the framework cannot be read from resources, written to the target directory, or if
     *                            the framework structure is invalid.
     * @throws URISyntaxException if the resource URI is malformed when accessing framework resources from a JAR file.
     */
    private String extractFrameworkFromResourcePath(String name, Path targetBaseDir, ClassLoader loader)
            throws IOException, URISyntaxException {
        URI uri = Objects.requireNonNull(loader.getResource("darwin/" + name)).toURI();
        if (Objects.equals(uri.getScheme(), "jar")) { // Extract from JAR
            try (FileSystem zipfs = FileSystems.newFileSystem(uri, Collections.emptyMap())) {
                Path sourcePath = zipfs.getPath("/darwin");
                return copyFramework(sourcePath, targetBaseDir, name);
            }
        } else { // Extract from resource directory
            Path sourcePath = Paths.get(Objects.requireNonNull(getClass().getResource("/darwin")).toURI());
            return copyFramework(sourcePath, targetBaseDir, name);
        }
    }

    private String copyFramework(Path sourcePath, Path targetBaseDir, String name) throws IOException {
        final String[] executablePath = {""};
        Files.walkFileTree(sourcePath, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                Files.createDirectories(targetBaseDir.resolve(sourcePath.relativize(dir).toString()));
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Path currentTarget = targetBaseDir.resolve(sourcePath.relativize(file).toString());
                Files.copy(file, currentTarget, StandardCopyOption.REPLACE_EXISTING);
                if (file.getFileName().toString().equals(name))
                    executablePath[0] = currentTarget.toString();

                return FileVisitResult.CONTINUE;
            }
        });

        return executablePath[0];
    }

    private void deleteDirectory(Path path) throws IOException {
        if (!Files.exists(path)) return;
        Files.walk(path).sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
    }

    protected static class NativeComponent {
        private String defaultName;
        private String darwinName;
        private String linuxX86Name;
        private String linuxX86_64Name;
        private String windowsX86Name;
        private String windowsX86_64Name;

        private NativeComponent() {
        }

        String getPlatformSpecificName() {
            if (Platform.isMac()) {
                return (darwinName != null) ? darwinName : defaultName;
            } else if (Platform.isLinux()) {
                if (Platform.is64Bit()) {
                    return (linuxX86_64Name != null) ? linuxX86_64Name : defaultName;
                } else {
                    return (linuxX86Name != null) ? linuxX86Name : defaultName;
                }
            } else if (Platform.isWindows()) {
                if (Platform.is64Bit()) {
                    return (windowsX86_64Name != null) ? windowsX86_64Name : defaultName;
                } else {
                    return (windowsX86Name != null) ? windowsX86Name : defaultName;
                }
            } else {
                throw new IllegalStateException("Failed to determine the component name for " + defaultName);
            }
        }

        public static class Builder {
            private final NativeComponent component = new NativeComponent();

            public NativeComponent.Builder setDefaultName(String name) {
                component.defaultName = name;
                return this;
            }

            public NativeComponent.Builder setDarwinName(String name) {
                component.darwinName = name;
                return this;
            }

            public NativeComponent.Builder setLinuxX86Name(String name) {
                component.linuxX86Name = name;
                return this;
            }

            public NativeComponent.Builder setLinuxX86_64Name(String name) {
                component.linuxX86_64Name = name;
                return this;
            }

            public NativeComponent.Builder setWindowsX86Name(String name) {
                component.windowsX86Name = name;
                return this;
            }

            public NativeComponent.Builder setWindowsX86_64Name(String name) {
                component.windowsX86_64Name = name;
                return this;
            }

            public NativeComponent build() {
                return component;
            }
        }
    }
}

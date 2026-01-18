package main

import (
   "bufio"
   "fmt"
   "os"
   "path/filepath"
   "regexp"
   "strings"
)

// visited keeps track of processed files to avoid infinite loops from circular dependencies.
var visited = make(map[string]bool)

// headerIndex maps a header's base name (e.g., "drmtypes.h") to its full relative path.
var headerIndex = make(map[string]string)

// buildHeaderIndex walks the directory tree from the root path and populates the headerIndex.
func buildHeaderIndex(root string) error {
   // Use filepath.Walk to recursively scan all files and directories.
   return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
      if err != nil {
         return err
      }
      // We are only interested in files with a .h extension.
      if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".h") {
         // Get the base name of the file (e.g., "drmtypes.h").
         filename := filepath.Base(path)
         // Store the full relative path in our index. Use filepath.ToSlash for consistent path separators.
         headerIndex[filename] = filepath.ToSlash(path)
      }
      return nil
   })
}

// findHeaders recursively finds and prints all headers included in a given file.
func findHeaders(filePath string, depth int) {
   // Clean the file path for consistent tracking in the 'visited' map.
   cleanPath, err := filepath.Abs(filePath)
   if err != nil {
      return // Silently ignore paths that can't be resolved.
   }

   // If we've already processed this file, stop to prevent infinite recursion.
   if visited[cleanPath] {
      return
   }
   visited[cleanPath] = true

   // Open the source file for reading.
   file, err := os.Open(filePath)
   if err != nil {
      return // Silently ignore files that cannot be opened.
   }
   defer file.Close()

   scanner := bufio.NewScanner(file)
   // Regex to find #include directives with either "header.h" or <header.h>.
   re := regexp.MustCompile(`^\s*#include\s*["<](.*)[">]`)

   // Read the file line by line.
   for scanner.Scan() {
      matches := re.FindStringSubmatch(scanner.Text())
      if len(matches) > 1 {
         // Extract the base header name (e.g., "drmtypes.h").
         headerBaseName := filepath.Base(matches[1])

         // Look up the full relative path in our pre-built index.
         if headerFullPath, found := headerIndex[headerBaseName]; found {
            // Print the found header path with indentation.
            fmt.Printf("%s%s\n", strings.Repeat("   ", depth+1), headerFullPath)
            // Recurse into the found header file.
            findHeaders(headerFullPath, depth+1)
         }
      }
   }

   if err := scanner.Err(); err != nil {
      fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filePath, err)
   }
}

func main() {
   // Expect the path to the C file as a command-line argument.
   if len(os.Args) < 2 {
      fmt.Println("Usage: go run main.go <path_to_c_file>")
      os.Exit(1)
   }
   rootCFile := os.Args[1]

   // Before starting, build an index of all available .h files from the current directory.
   fmt.Println("Indexing header files...")
   err := buildHeaderIndex(".")
   if err != nil {
      fmt.Fprintf(os.Stderr, "Error building header index: %v\n", err)
      os.Exit(1)
   }
   fmt.Println("...Done.\n")

   // Start the recursive search.
   findHeaders(rootCFile, 0)
}

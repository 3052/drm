package main

import (
   "encoding/json"
   "log"
   "os"
   "path/filepath"
   "strings"
)

// FileData holds the filename and content. The JSON field names are specified here.
type FileData struct {
   Filename string `json:"filename"`
   Content  string `json:"content"`
}

func main() {
   // 1. Find all .h and .c files in the current directory.
   sourceFiles, err := findSourceFiles(".")
   if err != nil {
      log.Fatalf("Error finding source files: %v", err)
   }
   if len(sourceFiles) == 0 {
      log.Println("Warning: No '.h' or '.c' files were found.")
      return
   }

   log.Printf("Found %d source files to process...", len(sourceFiles))

   // 2. Read the content of each file.
   var fileDataList []FileData
   for _, filename := range sourceFiles {
      content, err := os.ReadFile(filename)
      if err != nil {
         log.Fatalf("Error reading file %s: %v", filename, err)
      }

      // --- MODIFICATION IS HERE ---
      // Convert the byte slice to a string.
      contentString := string(content)
      // Remove all carriage returns (`\r`) to normalize newlines to LF (`\n`) only.
      cleanedContent := strings.ReplaceAll(contentString, "\r", "")

      // Append the struct with the cleaned content.
      fileDataList = append(fileDataList, FileData{Filename: filename, Content: cleanedContent})
   }

   // 3. Generate the JSON output.
   output, err := generateJSON(fileDataList)
   if err != nil {
      log.Fatalf("Error generating JSON output: %v", err)
   }

   // 4. Write the output directly to combined.json.
   outputFilename := "combined.json"
   err = os.WriteFile(outputFilename, []byte(output), 0644)
   if err != nil {
      log.Fatalf("Error writing to file %s: %v", outputFilename, err)
   }

   log.Printf("Success! Output has been saved to %s", outputFilename)
}

// findSourceFiles searches a directory for files with .h or .c extensions.
func findSourceFiles(rootDir string) ([]string, error) {
   var files []string
   err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
      if err != nil {
         return err
      }
      if !d.IsDir() && filepath.Dir(path) == rootDir {
         if strings.HasSuffix(d.Name(), ".h") || strings.HasSuffix(d.Name(), ".c") {
            files = append(files, d.Name())
         }
      }
      return nil
   })
   return files, err
}

// generateJSON converts the file data into a pretty-printed JSON formatted string.
func generateJSON(data []FileData) (string, error) {
   // MarshalIndent provides pretty-printing with indentation for readability.
   bytes, err := json.MarshalIndent(data, "", "  ")
   if err != nil {
      return "", err
   }
   return string(bytes), nil
}

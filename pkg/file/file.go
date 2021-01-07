package file

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func WriteFile(path, data string) bool {
	dirpath := filepath.Dir(path)
	if err := os.MkdirAll(dirpath, 0755); err != nil {
		log.Println(err)
		return false
	}

	f, err := os.Create(path)
	if err != nil {
		log.Println(err)
		f.Close()
		return false
	}
	f.Chmod(0600) // only you can access this file

	b, err := f.WriteString(data)
	if err != nil {
		log.Println(err)
		return false
	}
	log.Println(fmt.Sprint(b) + " bytes written successfully")

	if err = f.Close(); err != nil {
		log.Printf("failed to close file, %s", err.Error())
		return false
	}

	log.Println("file written successfully to " + path)
	return true
}

func WriteToFile(filename string, data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if ok := WriteFile(filename, string(jsonData)); !ok {
		return fmt.Errorf("failed to write file %v", filename)
	}
	return nil
}

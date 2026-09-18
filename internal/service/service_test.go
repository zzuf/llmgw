package service

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPlistAcceptedByLaunchdParser(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS plist validation")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.plist")
	dataDir := filepath.Join(dir, "Application Support", "LLMGateway")
	if err := os.WriteFile(path, Plist(filepath.Join(dataDir, "bin", "llmgw"), dataDir), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/plutil", "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plist rejected: %s (%v)", out, err)
	}
}

func TestPlistEscapesPaths(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "a & b", "bin", "gw")
	p := Plist(executable, filepath.Join(dir, "a <b>", "data"))
	decoder := xml.NewDecoder(strings.NewReader(string(p)))
	for {
		_, e := decoder.Token()
		if e != nil {
			if e.Error() != "EOF" {
				t.Fatal(e)
			}
			break
		}
	}
	if strings.Contains(string(p), executable) {
		t.Fatal("path unescaped")
	}
	if !strings.Contains(string(p), "--data-dir") || !strings.Contains(string(p), "<integer>63</integer>") {
		t.Fatal("missing launch properties")
	}
}

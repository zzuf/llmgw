// Package service manages a per-user LaunchAgent, never a root daemon.
package service

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const Label = "local.llmgw.gateway"

func escape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func Plist(executable, dataDir string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>` + Label + `</string>
<key>ProgramArguments</key><array><string>` + escape(executable) + `</string><string>serve</string><string>--data-dir</string><string>` + escape(dataDir) + `</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ProcessType</key><string>Background</string>
<key>WorkingDirectory</key><string>` + escape(dataDir) + `</string>
<key>StandardOutPath</key><string>` + escape(filepath.Join(dataDir, "logs", "service.log")) + `</string>
<key>StandardErrorPath</key><string>` + escape(filepath.Join(dataDir, "logs", "service.log")) + `</string>
<key>Umask</key><integer>63</integer>
</dict></plist>
`)
}
func plistPath() (string, error) {
	home, e := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist"), e
}
func userDomain() string { return "gui/" + strconv.Itoa(os.Getuid()) }
func check() error {
	if runtime.GOOS != "darwin" {
		return errors.New("launchd requires macOS")
	}
	if os.Geteuid() == 0 {
		return errors.New("run as your login user, not root")
	}
	return nil
}
func Install(executable, dataDir string) error {
	if e := check(); e != nil {
		return e
	}
	path, e := plistPath()
	if e != nil {
		return e
	}
	if _, e = os.Stat(path); e == nil {
		return errors.New("LaunchAgent already installed; uninstall it before replacing")
	}
	dataDir, e = filepath.Abs(dataDir)
	if e != nil {
		return e
	}
	for _, p := range []string{filepath.Dir(path), filepath.Join(dataDir, "bin"), filepath.Join(dataDir, "logs")} {
		if e = os.MkdirAll(p, 0700); e != nil {
			return e
		}
	}
	target := filepath.Join(dataDir, "bin", "llmgw")
	abs, e := filepath.Abs(executable)
	if e != nil {
		return e
	}
	if abs != target {
		src, e := os.Open(abs)
		if e != nil {
			return e
		}
		defer src.Close()
		dst, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if e != nil {
			if !os.IsExist(e) {
				return e
			}
			tmp := target + ".new"
			dst, e = os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
			if e != nil {
				return e
			}
			_, e = io.Copy(dst, src)
			closeErr := dst.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
			if e = os.Rename(tmp, target); e != nil {
				return e
			}
		} else {
			_, e = io.Copy(dst, src)
			closeErr := dst.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	if e = os.WriteFile(path, Plist(target, dataDir), 0600); e != nil {
		return e
	}
	return Start()
}
func Start() error {
	if e := check(); e != nil {
		return e
	}
	p, e := plistPath()
	if e != nil {
		return e
	}
	out, e := exec.Command("/bin/launchctl", "bootstrap", userDomain(), p).CombinedOutput()
	if e != nil {
		return fmt.Errorf("launchctl bootstrap: %w (%s)", e, strings.TrimSpace(string(out)))
	}
	return nil
}
func Stop() error {
	if e := check(); e != nil {
		return e
	}
	out, e := exec.Command("/bin/launchctl", "bootout", userDomain()+"/"+Label).CombinedOutput()
	if e != nil {
		return fmt.Errorf("launchctl bootout: %w (%s)", e, strings.TrimSpace(string(out)))
	}
	return nil
}
func Uninstall() error {
	if e := check(); e != nil {
		return e
	}
	_ = Stop()
	p, e := plistPath()
	if e != nil {
		return e
	}
	return os.Remove(p)
}
func Status() (string, error) {
	if e := check(); e != nil {
		return "", e
	}
	out, e := exec.Command("/bin/launchctl", "print", userDomain()+"/"+Label).CombinedOutput()
	return string(out), e
}

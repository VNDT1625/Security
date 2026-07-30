//go:build windows

// This program is a harmless, deterministic Cloud Sandbox contract fixture.
// It never collects credentials and never opens a network connection. Run it
// only inside a disposable Windows test VM: it intentionally creates a script,
// starts cmd.exe, and writes a training-only HKCU Run value so the Auto agent
// has attributable process, file, and registry evidence to observe.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	hkeyCurrentUser = uintptr(0x80000001)
	keySetValue     = uintptr(0x0002)
	regSZ           = uintptr(1)
)

var (
	advapi32        = syscall.NewLazyDLL("advapi32.dll")
	regCreateKeyExW = advapi32.NewProc("RegCreateKeyExW")
	regSetValueExW  = advapi32.NewProc("RegSetValueExW")
	regCloseKey     = advapi32.NewProc("RegCloseKey")
)

func writeTrainingRunValue(executable string) error {
	keyPath, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Run`)
	if err != nil {
		return err
	}
	var key syscall.Handle
	status, _, _ := regCreateKeyExW.Call(
		hkeyCurrentUser,
		uintptr(unsafe.Pointer(keyPath)),
		0, 0, 0, keySetValue, 0,
		uintptr(unsafe.Pointer(&key)),
		0,
	)
	if status != 0 {
		return fmt.Errorf("RegCreateKeyExW status=%d", status)
	}
	defer regCloseKey.Call(uintptr(key))

	name, err := syscall.UTF16PtrFromString("PrewisePhishingTraining")
	if err != nil {
		return err
	}
	value, err := syscall.UTF16FromString(executable)
	if err != nil {
		return err
	}
	status, _, _ = regSetValueExW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(name)),
		0,
		regSZ,
		uintptr(unsafe.Pointer(&value[0])),
		uintptr(len(value)*2),
	)
	if status != 0 {
		return fmt.Errorf("RegSetValueExW status=%d", status)
	}
	return nil
}

func main() {
	workDir, err := os.Getwd()
	if err != nil {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		return
	}

	marker := filepath.Join(workDir, "TRAINING_ONLY_FAKE_LOGIN.html")
	droppedScript := filepath.Join(workDir, "credential-harvest-simulator.bat")
	_ = os.WriteFile(marker, []byte("<!doctype html><title>TRAINING ONLY</title><h1>Phishing simulation - no credential collection</h1>"), 0o600)
	_ = os.WriteFile(droppedScript, []byte("@echo off\r\necho PREWISE_PHISHING_SIMULATION_ONLY>simulation-output.txt\r\n"), 0o600)

	if err := writeTrainingRunValue(executable); err != nil {
		_ = os.WriteFile(filepath.Join(workDir, "registry-simulation-error.txt"), []byte(err.Error()), 0o600)
	}
	cmd := exec.Command("cmd.exe", "/d", "/c", droppedScript)
	cmd.Dir = workDir
	_ = cmd.Start()
	time.Sleep(18 * time.Second)
}

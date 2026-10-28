//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSecureWindowsPathsRoundTrip(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := SecureDir(directory); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecureDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "private.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SecureFile(path); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecureFile(path); err != nil {
		t.Fatal(err)
	}
	sid, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecureFile(path); err == nil {
		t.Fatal("必须拒绝允许其他用户访问的文件")
	}
	if err := SecureFile(path); err != nil {
		t.Fatal(err)
	}
}

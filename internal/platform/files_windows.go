//go:build windows

package platform

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func SecureDir(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("路径不是目录: %s", path)
		}
		return ValidateSecureDir(path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return setOwnerOnlyACL(path, true)
}

func SecureFile(path string) error {
	return setOwnerOnlyACL(path, false)
}

func ValidateSecureDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("路径不是目录: %s", path)
	}
	return verifyOwnerOnlyACL(path)
}

func ValidateSecureFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("路径不是普通文件: %s", path)
	}
	return verifyOwnerOnlyACL(path)
}

func ValidateTrustedDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("路径不是目录: %s", path)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("读取 Windows 目录 ACL: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("Windows 目录 ACL 无法验证: %s", path)
	}
	broadSIDs, err := broadWriteSIDs()
	if err != nil {
		return err
	}
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	writeMask := windows.ACCESS_MASK(windows.GENERIC_ALL|windows.GENERIC_WRITE|windows.FILE_GENERIC_WRITE|
		windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER) | fileDeleteChild
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("读取 Windows 目录 ACL 条目: %w", err)
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			if ace.Header.AceType == 5 || ace.Header.AceType == 9 || ace.Header.AceType == 11 {
				return fmt.Errorf("Windows 目录包含无法安全验证的 Allow ACE: %s", path)
			}
			continue
		}
		if ace.Mask&writeMask == 0 {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, broadSID := range broadSIDs {
			if aceSID.Equals(broadSID) {
				return fmt.Errorf("Windows 目录可被其他用户写入: %s", path)
			}
		}
	}
	return nil
}

func broadWriteSIDs() ([]*windows.SID, error) {
	types := []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,
		windows.WinAuthenticatedUserSid,
		windows.WinBuiltinUsersSid,
		windows.WinBuiltinGuestsSid,
	}
	result := make([]*windows.SID, 0, len(types))
	for _, sidType := range types {
		sid, err := windows.CreateWellKnownSid(sidType)
		if err != nil {
			return nil, fmt.Errorf("创建 Windows 广泛用户 SID: %w", err)
		}
		result = append(result, sid)
	}
	return result, nil
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("读取当前 Windows 用户 SID: %w", err)
	}
	return user.User.Sid, nil
}

func setOwnerOnlyACL(path string, directory bool) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("生成 Windows ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return fmt.Errorf("设置 Windows ACL: %w", err)
	}
	return nil
}

func verifyOwnerOnlyACL(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("读取 Windows ACL: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("ACL 不是当前用户独占: %s", path)
	}
	var permissions windows.ACCESS_MASK
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("读取 Windows ACL 条目: %w", err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			return fmt.Errorf("ACL 不是当前用户独占: %s", path)
		}
		// Windows 会将目录权限拆为当前对象和仅供子对象继承的条目，并映射通用权限。
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
			permissions |= ace.Mask
		}
	}
	const fileAllAccess windows.ACCESS_MASK = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
	if permissions&windows.GENERIC_ALL == 0 && permissions&fileAllAccess != fileAllAccess {
		return fmt.Errorf("ACL 不是当前用户独占: %s", path)
	}
	return nil
}

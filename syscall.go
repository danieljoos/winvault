// Copyright (c) 2017 Daniel Joos
// Distributed under MIT license (see file LICENSE).

package winvault

import (
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/google/uuid"
)

var (
	vaultcli = syscall.NewLazyDLL("vaultcli.dll")

	procVaultCloseVault      = vaultcli.NewProc("VaultCloseVault")
	procVaultEnumerateItems  = vaultcli.NewProc("VaultEnumerateItems")
	procVaultEnumerateVaults = vaultcli.NewProc("VaultEnumerateVaults")
	procVaultFree            = vaultcli.NewProc("VaultFree")
	procVaultGetInformation  = vaultcli.NewProc("VaultGetInformation")
	procVaultGetItem         = vaultcli.NewProc("VaultGetItem")
	procVaultOpenVault       = vaultcli.NewProc("VaultOpenVault")

	useAPI7 = isWindows7()
)

type sysVaultInformationKind uint32
type sysVaultElementType int32

const (
	vaultInformationKindName  sysVaultInformationKind = 0x01
	vaultInformationKindPath7 sysVaultInformationKind = 0x08
	vaultInformationKindPath8 sysVaultInformationKind = 0x04

	vaultElementTypeUndefined       sysVaultElementType = -1
	vaultElementTypeBoolean         sysVaultElementType = 0
	vaultElementTypeShort           sysVaultElementType = 1
	vaultElementTypeUnsignedShort   sysVaultElementType = 2
	vaultElementTypeInteger         sysVaultElementType = 3
	vaultElementTypeUnsignedInteger sysVaultElementType = 4
	vaultElementTypeDouble          sysVaultElementType = 5
	vaultElementTypeGUID            sysVaultElementType = 6
	vaultElementTypeString          sysVaultElementType = 7
	vaultElementTypeByteArray       sysVaultElementType = 8
	vaultElementTypeTimeStamp       sysVaultElementType = 9
	vaultElementTypeProtectedArray  sysVaultElementType = 10
	vaultElementTypeAttribute       sysVaultElementType = 11
	vaultElementTypeSid             sysVaultElementType = 12
	vaultElementTypeLast            sysVaultElementType = 13
)

type sysVaultInformationString struct {
	Kind  sysVaultInformationKind
	Value *uint16
}

type sysVaultElement struct {
	ID   int32
	_    int32
	Type sysVaultElementType
	_    int32
}

type sysVaultElementString struct {
	sysVaultElement
	Data *uint16
}

type sysVaultElementByteArray struct {
	sysVaultElement
	Length uint32
	Value  uintptr
}

type sysVaultItem7 struct {
	ID              uuid.UUID
	Name            *uint16
	Resource        *sysVaultElement
	Identity        *sysVaultElement
	Authenticator   *sysVaultElement
	Filetime        syscall.Filetime
	Flags           uint32
	PropertiesCount uint32
	Properties      uintptr
}

type sysVaultItem8 struct {
	ID              uuid.UUID
	Name            *uint16
	Resource        *sysVaultElement
	Identity        *sysVaultElement
	Authenticator   *sysVaultElement
	PackageSid      uintptr
	Filetime        syscall.Filetime
	Flags           uint32
	PropertiesCount uint32
	Properties      uintptr
}

// isWindows7 returns if the program is running on Windows 7.
func isWindows7() bool {
	ver, _ := windows.GetVersion()
	verMajor := byte(ver)
	verMinor := uint8(ver >> 8)
	return verMajor == 6 && verMinor == 1
}

// sysVaultEnumerateVaults calls the 'VaultEnumerateVaults' function of the
// Windows Vault API.
func sysVaultEnumerateVaults() ([]uuid.UUID, error) {
	var count int
	var guids uintptr
	ret, _, _ := procVaultEnumerateVaults.Call(
		0,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&guids)),
	)
	if ret != windows.NO_ERROR {
		return nil, (syscall.Errno)(ret)
	}
	defer procVaultFree.Call(guids)
	guidsSlice := *(*[]uuid.UUID)(unsafe.Pointer(&reflect.SliceHeader{
		Data: guids,
		Len:  count,
		Cap:  count,
	}))
	result := make([]uuid.UUID, count)
	copy(result, guidsSlice)
	return result, nil
}

// sysVaultOpenVault calls the 'VaultOpenVault' function of the Windows Vault
// API.
func sysVaultOpenVault(id uuid.UUID) (syscall.Handle, error) {
	var handle syscall.Handle
	ret, _, _ := procVaultOpenVault.Call(
		uintptr(unsafe.Pointer(&id)),
		0,
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != windows.NO_ERROR {
		return 0, (syscall.Errno)(ret)
	}
	return handle, nil
}

// sysVaultCloseVault calls the 'VaultCloseVault' function of the Windows Vault
// API.
func sysVaultCloseVault(handle syscall.Handle) error {
	ret, _, _ := procVaultCloseVault.Call(
		uintptr(handle),
	)
	if ret != windows.NO_ERROR {
		return (syscall.Errno)(ret)
	}
	return nil
}

// sysVaultGetInformationString calls the 'VaultGetInformation' function of the
// Windows Vault API and returns the result as string.
func sysVaultGetInformationString(handle syscall.Handle, kind sysVaultInformationKind) (string, error) {
	info := sysVaultInformationString{Kind: kind}
	ret, _, _ := procVaultGetInformation.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&info)),
	)
	if ret != windows.NO_ERROR {
		return "", (syscall.Errno)(ret)
	}
	return utf16PtrToString(info.Value), nil
}

// sysVaultEnumerateItems calls the 'VaultEnumerateItems' function of the
// Windows Vault API. For each item it calls the sysVaultGetItem function.
func sysVaultEnumerateItems(handle syscall.Handle) ([]VaultItem, error) {
	var count int
	var items uintptr
	ret, _, _ := procVaultEnumerateItems.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&items)),
	)
	if ret != windows.NO_ERROR {
		return nil, (syscall.Errno)(ret)
	}
	defer procVaultFree.Call(items)
	var result []VaultItem
	if useAPI7 {
		// Windows 7: Fetch all vault-items
		itemsSlice := *(*[]sysVaultItem7)(unsafe.Pointer(&reflect.SliceHeader{
			Data: items,
			Len:  count,
			Cap:  count,
		}))
		for _, descriptor := range itemsSlice {
			item, err := sysVaultGetItem7(handle, descriptor)
			if err == nil {
				result = append(result, *item)
			}
		}
	} else {
		// Windows 8 (and above): Fetch all vault-items
		itemsSlice := *(*[]sysVaultItem8)(unsafe.Pointer(&reflect.SliceHeader{
			Data: items,
			Len:  count,
			Cap:  count,
		}))
		for _, descriptor := range itemsSlice {
			item, err := sysVaultGetItem8(handle, descriptor)
			if err == nil {
				result = append(result, *item)
			}
		}
	}
	return result, nil
}

// sysVaultGetItem7 calls the 'VaultGetItem' function of the Windows Vault API
// for Windows 7. The result is converted to a more usable structure.
func sysVaultGetItem7(handle syscall.Handle, descriptor sysVaultItem7) (*VaultItem, error) {
	var item *sysVaultItem7
	ret, _, _ := procVaultGetItem.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&descriptor.ID)),
		uintptr(unsafe.Pointer(descriptor.Resource)),
		uintptr(unsafe.Pointer(descriptor.Identity)),
		0,
		0,
		uintptr(unsafe.Pointer(&item)),
	)
	if ret != windows.NO_ERROR {
		return nil, (syscall.Errno)(ret)
	}
	defer procVaultFree.Call(uintptr(unsafe.Pointer(item)))
	return convertToVaultItem7(item), nil
}

// sysVaultGetItem8 calls the 'VaultGetItem' function of the Windows Vault API
// for Windows 8 and above.  The result is converted to a more usable structure.
func sysVaultGetItem8(handle syscall.Handle, descriptor sysVaultItem8) (*VaultItem, error) {
	var item *sysVaultItem8
	ret, _, _ := procVaultGetItem.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&descriptor.ID)),
		uintptr(unsafe.Pointer(descriptor.Resource)),
		uintptr(unsafe.Pointer(descriptor.Identity)),
		descriptor.PackageSid,
		0,
		0,
		uintptr(unsafe.Pointer(&item)),
	)
	if ret != windows.NO_ERROR {
		return nil, (syscall.Errno)(ret)
	}
	defer procVaultFree.Call(uintptr(unsafe.Pointer(item)))
	return convertToVaultItem8(item), nil
}

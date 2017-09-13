// Copyright (c) 2017 Daniel Joos
// Distributed under MIT license (see file LICENSE).

package winvault

import (
	"reflect"
	"time"
	"unicode/utf16"
	"unsafe"
)

// uf16PtrToString creates a Go string from a pointer to a UTF16 encoded zero-terminated string.
// Such pointers are returned from the Windows API calls.
// The function creates a copy of the string.
func utf16PtrToString(wstr *uint16) string {
	if wstr != nil {
		for len := 0; ; len++ {
			ptr := unsafe.Pointer(uintptr(unsafe.Pointer(wstr)) + uintptr(len)*unsafe.Sizeof(*wstr)) // see https://golang.org/pkg/unsafe/#Pointer (3)
			if *(*uint16)(ptr) == 0 {
				return string(utf16.Decode(*(*[]uint16)(unsafe.Pointer(&reflect.SliceHeader{
					Data: uintptr(unsafe.Pointer(wstr)),
					Len:  len,
					Cap:  len,
				}))))
			}
		}
	}
	return ""
}

// goBytes copies the given C byte array to a Go byte array (see `C.GoBytes`).
// This function avoids having cgo as dependency.
func goBytes(src uintptr, len uint32) []byte {
	if src == uintptr(0) {
		return []byte{}
	}
	rv := make([]byte, len)
	copy(rv, *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Data: src,
		Len:  int(len),
		Cap:  int(len),
	})))
	return rv
}

// convertToVaultItemElement converts the given sysVaultElement to a structure
// more usable in golang. All values are copied and the sysVaultElement can
// therefore be freed afterwards.
// The function distinguishes between different types of vault-item elements.
// For unsupported types the function returns nil.
func convertToVaultItemElement(elem *sysVaultElement) VaultItemElement {
	if elem != nil {
		switch elem.Type {
		case vaultElementTypeString:
			return &VaultItemElementString{
				id:    elem.ID,
				value: utf16PtrToString((*sysVaultElementString)(unsafe.Pointer(elem)).Data),
			}
		case vaultElementTypeByteArray:
			elemBA := (*sysVaultElementByteArray)(unsafe.Pointer(elem))
			return &VaultItemElementByteArray{
				id:    elem.ID,
				value: goBytes(elemBA.Value, elemBA.Length),
			}
		}
	}
	return nil
}

// convertToVaultItem7 implements the vault-item conversion for the Windows 7
// version of the Vault API.
func convertToVaultItem7(item *sysVaultItem7) *VaultItem {
	return &VaultItem{
		ID:            item.ID,
		Name:          utf16PtrToString(item.Name),
		Resource:      convertToVaultItemElement(item.Resource),
		Identity:      convertToVaultItemElement(item.Identity),
		Authenticator: convertToVaultItemElement(item.Authenticator),
		LastModified:  time.Unix(0, item.Filetime.Nanoseconds()),
	}
}

// convertToVaultItem8 implements the vault-item conversion for the Windows 8
// version of the Vault API.
func convertToVaultItem8(item *sysVaultItem8) *VaultItem {
	return &VaultItem{
		ID:            item.ID,
		Name:          utf16PtrToString(item.Name),
		Resource:      convertToVaultItemElement(item.Resource),
		Identity:      convertToVaultItemElement(item.Identity),
		Authenticator: convertToVaultItemElement(item.Authenticator),
		LastModified:  time.Unix(0, item.Filetime.Nanoseconds()),
	}
}

// Copyright (c) 2017 Daniel Joos
// Distributed under MIT license (see file LICENSE).

// Package winvault provides primitives for accessing the undocumented Windows Vault API.
// The package uses the functions exposed by the vaulcli.dll library to access
// Windows credential vaults. For example this includes the web-credentials vault
// that is used by Internet Explorer and Edge to store login form information.
//
// At the moment, the package provides read-only access to the vault data.
//
// As the Windows Vault API is not officially supported nor documented, the main
// concepts and function signatures have been taken from the following sources:
//
//  - http://www.oxid.it/downloads/vaultdump.txt
//  - https://github.com/EmpireProject/Empire
//  - https://github.com/rapid7/meterpreter
//
package winvault

import (
	"syscall"

	"github.com/google/uuid"
)

var (
	// VaultIDWebCredentials holds the fixed UUID of the web-credentials vault.
	// This vault is used by Internet Explorer and Edge (at least on Windows 10)
	// to store login information.
	VaultIDWebCredentials = uuid.Must(uuid.Parse("42c4f44b-8a9b-a041-b380-dd4a704ddb28"))
)

// Open opens the vault with the given ID.
// The function fetches the name and path property of the vault, as well.
// On success, the function returns the opened vault.
// An error is returned otherwise.
func Open(vaultID uuid.UUID) (*Vault, error) {
	// Open the vault
	handle, err := sysVaultOpenVault(vaultID)
	if err != nil {
		return nil, err
	}
	// Fetch the vault's name
	name, err := sysVaultGetInformationString(handle, vaultInformationKindName)
	if err != nil {
		return nil, err
	}
	// Fetch the vault's path
	var path string
	if useAPI7 {
		path, err = sysVaultGetInformationString(handle, vaultInformationKindPath7)
	} else {
		path, err = sysVaultGetInformationString(handle, vaultInformationKindPath8)
	}
	if err != nil {
		return nil, err
	}
	// Build the resulting vault object
	return &Vault{
		ID:     vaultID,
		Name:   name,
		Path:   path,
		handle: handle,
	}, nil
}

// OpenWebCredentials opens the web-credentials vault.
// The function calls the Open() function with the fixed UUID of the
// web-credentials vault.
// On success, the function returns the opened web-credentials vault.
// It returns an error otherwise.
func OpenWebCredentials() (*Vault, error) {
	return Open(VaultIDWebCredentials)
}

// List returns a list of IDs of available vaults.
// The function does not open any vault.
func List() ([]uuid.UUID, error) {
	return sysVaultEnumerateVaults()
}

// Close closes an open vault.
// Open vaults should always be closed after use to free memory reserved by the
// Windows Vault API.
// The function invalidates the vault handle. Subsequent operations on this
// vault object will fail.
func (t *Vault) Close() {
	sysVaultCloseVault(t.handle)
	t.handle = syscall.InvalidHandle
}

// Items returns the credential items of this vault.
// The function enumerates and fetches all of the vault's items including their
// secret strings (e.g. the password). If one of the items cannot be fetched it
// will be silently ignored.
//
// The values inside the returned vault items are copied into the managed golang
// memory. Therefore they can be used even after closing the vault.
func (t *Vault) Items() ([]VaultItem, error) {
	return sysVaultEnumerateItems(t.handle)
}

// Copyright (c) 2017 Daniel Joos
// Distributed under MIT license (see file LICENSE).

package winvault

import (
	"syscall"
	"time"

	"github.com/google/uuid"
)

// Vault represents an open credential vault.
// A vault has a unique ID and a name.
// The vault's path points to where the credential data is stored on the disk.
// Open vaults should be closed after use.
type Vault struct {
	ID   uuid.UUID
	Name string
	Path string

	handle syscall.Handle
}

// VaultItem represents a credential item in a vault.
// A vault item has a unique ID and a friendly name (the latter might contain
// the name of the application that owns the credentials, e.g. for
// web-credentials the name is set to "Internet Explorer").
//
// The Resource property contains the name of the resource the credential is
// used for, e.g. this can be the URL in case of web-credentials.
// The Identity property holds information about the credential's identity, e.g.
// the user name in case of web-credentials.
// The Authenticator property holds the actual credential secret - for web-
// credentials this would be the password.
type VaultItem struct {
	ID            uuid.UUID
	Name          string
	Resource      VaultItemElement
	Identity      VaultItemElement
	Authenticator VaultItemElement
	LastModified  time.Time
}

// VaultItemElement defines an interface for property-elements of vault items.
// Such elements can be of different types and therefore this interface defines
// a method for getting the actual type of the element.
// The actual values can be fetched using accessor methods for the different
// types. For now, the element types 'string' and 'byte-array' are supported.
type VaultItemElement interface {
	ID() int32
	Type() ElementType
	AsString() string
	AsByteArray() []byte
}

// VaultItemElementString implements the VaultItemElement interface for elements
// of type string.
type VaultItemElementString struct {
	id    int32
	value string
}

// VaultItemElementByteArray implements the VaultItemElement interface for
// elements of type byte-array.
type VaultItemElementByteArray struct {
	id    int32
	value []byte
}

// ElementType is an enumeration used to distinguish the types of vault-item
// elements.
type ElementType int

const (
	// ElementTypeString corresponds to string elements.
	ElementTypeString ElementType = iota

	// ElementTypeByteArray corresponds to byte-array elements.
	ElementTypeByteArray
)

// Type always returns ElementTypeString.
func (t *VaultItemElementString) Type() ElementType {
	return ElementTypeString
}

// ID returns the element ID.
func (t *VaultItemElementString) ID() int32 {
	return t.id
}

// AsString returns the element's string value.
func (t *VaultItemElementString) AsString() string {
	return t.value
}

// AsByteArray returns the byte representation of the element's string value.
func (t *VaultItemElementString) AsByteArray() []byte {
	return []byte(t.value)
}

// Type always returns ElementTypeByteArray.
func (t *VaultItemElementByteArray) Type() ElementType {
	return ElementTypeByteArray
}

// ID returns the element ID.
func (t *VaultItemElementByteArray) ID() int32 {
	return t.id
}

// AsString returns the string representation of the element's byte-array value.
func (t *VaultItemElementByteArray) AsString() string {
	return string(t.value)
}

// AsByteArray returns the element's byte-array value.
func (t *VaultItemElementByteArray) AsByteArray() []byte {
	return t.value
}

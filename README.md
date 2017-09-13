# winvault
Package winvault provides primitives for accessing the undocumented Windows Vault API.

[![GoDoc](https://godoc.org/github.com/danieljoos/winvault?status.svg)](https://godoc.org/github.com/danieljoos/winvault)

# Installation

```Go
go get github.com/danieljoos/winvault
```

# Usage

### List Web Credentials

The following example prints the credentials stored by Internet Explorer:

```Go
package main

import (
	"fmt"

	"github.com/danieljoos/winvault"
)

func main() {
	vault, err := winvault.OpenWebCredentials()
	if err != nil {
		panic(err)
	}
	defer vault.Close()

	items, err := vault.Items()
	if err != nil {
		panic(err)
	}
	for _, item := range items {
		fmt.Println("---")
		fmt.Println("Application:", item.Name)
		fmt.Println("Resource:", item.Resource.AsString())
		fmt.Println("Username:", item.Identity.AsString())
		fmt.Println("Password:", item.Authenticator.AsString())
	}
}
```

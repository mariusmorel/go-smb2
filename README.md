smb2
====

Warning
-------

This library is modified for specific security recon use cases.

For a production ready library, please use the original [Hiroshi Ioka's version](https://github.com/hirochachacha/go-smb2).

Description
-----------

SMB2/3 client implementation.

Installation
------------

`go get github.com/LeakIX/go-smb2@master`

Documentation
-------------

http://godoc.org/github.com/LeakIX/go-smb2

Examples
--------

### List share names ###

```go
package main

import (
	"fmt"
	"net"
	"github.com/LeakIX/ntlmssp"
	"github.com/LeakIX/go-smb2"
)

func main() {
	conn, err := net.Dial("tcp", "SERVERNAME:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	ntlmsspClient, err := ntlmssp.NewClient(
		ntlmssp.SetCompatibilityLevel(3),
		ntlmssp.SetUserInfo("Guest", ""),
		ntlmssp.SetDomain("MicrosoftAccount"))
	if err != nil {
		panic(err)
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMSSPInitiator{
			NTLMSSPClient: ntlmsspClient,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		log.Println(ntlmsspClient.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvDNSComputerName))
		panic(err)
	}
	defer s.Logoff()

	names, err := s.ListSharenames()
	if err != nil {
		panic(err)
	}

	for _, name := range names {
		fmt.Println(name)
	}
}
```

### File manipulation ###

```go
package main

import (
	"io"
	"io/ioutil"
	"net"
	"github.com/LeakIX/ntlmssp"
	"github.com/LeakIX/go-smb2"
)

func main() {
	conn, err := net.Dial("tcp", "SERVERNAME:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ntlmsspClient, err := ntlmssp.NewClient(
		ntlmssp.SetCompatibilityLevel(3),
		ntlmssp.SetUserInfo("Guest", ""),
		ntlmssp.SetDomain("MicrosoftAccount"))
	if err != nil {
		panic(err)
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMSSPInitiator{
			NTLMSSPClient: ntlmsspClient,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	fs, err := s.Mount("SHARENAME")
	if err != nil {
		panic(err)
	}
	defer fs.Umount()

	f, err := fs.Create("hello.txt")
	if err != nil {
		panic(err)
	}
	defer fs.Remove("hello.txt")
	defer f.Close()

	_, err = f.Write([]byte("Hello world!"))
	if err != nil {
		panic(err)
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		panic(err)
	}

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bs))
}
```

### Check error types ###

```go
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"github.com/LeakIX/ntlmssp"
	"github.com/LeakIX/go-smb2"
)

func main() {
	conn, err := net.Dial("tcp", "SERVERNAME:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ntlmsspClient, err := ntlmssp.NewClient(
		ntlmssp.SetCompatibilityLevel(3),
		ntlmssp.SetUserInfo("Guest", ""),
		ntlmssp.SetDomain("MicrosoftAccount"))
	if err != nil {
		panic(err)
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMSSPInitiator{
			NTLMSSPClient: ntlmsspClient,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	fs, err := s.Mount("SHARENAME")
	if err != nil {
		panic(err)
	}
	defer fs.Umount()

	_, err = fs.Open("notExist.txt")

	fmt.Println(os.IsNotExist(err)) // true
	fmt.Println(os.IsExist(err))    // false

	fs.WriteFile("hello2.txt", []byte("test"), 0444)
	err = fs.WriteFile("hello2.txt", []byte("test2"), 0444)
	fmt.Println(os.IsPermission(err)) // true

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	_, err = fs.WithContext(ctx).Open("hello.txt")

	fmt.Println(os.IsTimeout(err)) // true
}
```

### Glob and WalkDir through FS interface ###

```go
package main

import (
	"fmt"
	"net"
	iofs "io/fs"
	"github.com/LeakIX/ntlmssp"
	"github.com/LeakIX/go-smb2"
)

func main() {
	conn, err := net.Dial("tcp", "SERVERNAME:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ntlmsspClient, err := ntlmssp.NewClient(
		ntlmssp.SetCompatibilityLevel(3),
		ntlmssp.SetUserInfo("Guest", ""),
		ntlmssp.SetDomain("MicrosoftAccount"))
	if err != nil {
		panic(err)
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMSSPInitiator{
			NTLMSSPClient: ntlmsspClient,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	fs, err := s.Mount("SHARENAME")
	if err != nil {
		panic(err)
	}
	defer fs.Umount()

	matches, err := iofs.Glob(fs.DirFS("."), "*")
	if err != nil {
		panic(err)
	}
	for _, match := range matches {
		fmt.Println(match)
	}

	err = iofs.WalkDir(fs.DirFS("."), ".", func(path string, d fs.DirEntry, err error) error {
		fmt.Println(path, d, err)

		return nil
	})
	if err != nil {
		panic(err)
	}
}
```

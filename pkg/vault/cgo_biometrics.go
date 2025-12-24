//go:build cgo
// +build cgo

package vault

/*
#include "vault_core.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

// SecureStore stores credentials in the system secure store
func SecureStore(service, user, password string) error {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))

	cUser := C.CString(user)
	defer C.free(unsafe.Pointer(cUser))

	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	result := C.vault_secure_store(cService, cUser, cPassword)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return err
		}
		return &VaultError{Code: ErrorCode(result), Message: "Failed to store credential"}
	}
	return nil
}

// SecureGet retrieves credentials from the system secure store
func SecureGet(service, user string) (string, error) {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))

	cUser := C.CString(user)
	defer C.free(unsafe.Pointer(cUser))

	var cPassword *C.char
	result := C.vault_secure_get(cService, cUser, &cPassword)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return "", err
		}
		return "", &VaultError{Code: ErrorCode(result), Message: "Failed to get credential"}
	}

	password := C.GoString(cPassword)
	C.vault_free_string(cPassword)
	return password, nil
}

// SecureDelete deletes credentials from the system secure store
func SecureDelete(service, user string) error {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))

	cUser := C.CString(user)
	defer C.free(unsafe.Pointer(cUser))

	result := C.vault_secure_delete(cService, cUser)
	if result != C.ERROR_SUCCESS {
		if err := getLastError(); err != nil {
			return err
		}
		return &VaultError{Code: ErrorCode(result), Message: "Failed to delete credential"}
	}
	return nil
}

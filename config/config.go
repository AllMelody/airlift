// Package config holds airliftd's on-disk configuration. It is intentionally
// compatible with the pre-rewrite config file: unknown keys (e.g. the old
// Twitter/Syntax settings) are ignored, and passwords are verified with the
// same scrypt parameters, so existing deployments keep working untouched.
package config

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/scrypt"

	"ktkr.us/pkg/airlift/shorthash"
)

// scrypt parameters. These match the values used by the original
// ktkr.us/pkg/gas/auth package (N = 2<<13, r = 8, p = 1, keyLen = 32) so that
// password hashes written by older versions still verify.
const (
	scryptN      = 1 << 14 // 16384
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 32
)

// OnSave, if set, is called with the new config whenever it is persisted.
var OnSave func(*Config)

var (
	sharedConfig atomic.Value // *Config
	confPath     string
	Default      Config
	mu           sync.Mutex // serializes writes to the config file
)

// Config is airliftd's global configuration.
type Config struct {
	Host          string `json:"Host"`
	Port          int    `json:"Port"`
	Password      []byte `json:"Password"`
	Salt          []byte `json:"Salt"`
	Directory     string `json:"Directory"`
	HashLen       int    `json:"HashLen"`
	MaxAgeEnable  bool   `json:"MaxAgeEnable"`
	Age           int    `json:"Age"` // max age of uploads in days
	MaxSizeEnable bool   `json:"MaxSizeEnable"`
	Size          int64  `json:"Size"` // max total size of uploads in MB
	AppendExt     bool   `json:"AppendExt"`
}

// MaxAge satisfies the cache.Config interface.
func (c Config) MaxAge() int {
	if c.MaxAgeEnable {
		return c.Age
	}
	return 0
}

// MaxSize satisfies the cache.Config interface.
func (c Config) MaxSize() int64 {
	if c.MaxSizeEnable {
		return c.Size
	}
	return 0
}

// MaxCount satisfies the cache.Config interface.
func (c Config) MaxCount() int { return 0 }

// Refresh satisfies the cache.Config interface.
func (c *Config) Refresh() { *c = *Get() }

// ProcessHash satisfies the cache.Config interface.
func (c *Config) ProcessHash(buf []byte) string {
	return shorthash.Make(buf, c.HashLen)
}

// HasPassword reports whether a password has been configured.
func (c *Config) HasPassword() bool { return len(c.Password) > 0 }

// SetPass updates the config with a new password hash and a fresh random salt.
func (c *Config) SetPass(pass string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	hash, err := hashPass(pass, salt)
	if err != nil {
		return err
	}
	c.Salt = salt
	c.Password = hash
	return nil
}

// VerifyPass reports whether pass matches the stored password hash. It is
// constant-time and returns false if no password is configured.
func (c *Config) VerifyPass(pass string) bool {
	if !c.HasPassword() {
		return false
	}
	hash, err := hashPass(pass, c.Salt)
	if err != nil {
		return false
	}
	return hmac.Equal(hash, c.Password)
}

func hashPass(pass string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(pass), salt, scryptN, scryptR, scryptP, scryptKeyLen)
}

// Init loads the config from disk into memory, creating it with defaults if it
// doesn't exist yet.
func Init(filePath string) error {
	confPath = filePath
	c, err := Load()
	if err != nil {
		return err
	}
	sharedConfig.Store(c)
	return nil
}

// Get returns a copy of the current config, safe for the caller to mutate.
func Get() *Config {
	c := new(Config)
	*c = *sharedConfig.Load().(*Config)
	return c
}

// Set stores c as the current config and persists it to disk.
func Set(c *Config) error {
	sharedConfig.Store(c)
	if err := Save(c); err != nil {
		return err
	}
	if OnSave != nil {
		OnSave(c)
	}
	return nil
}

// Reload re-reads the config from disk.
func Reload() error {
	c, err := Load()
	if err != nil {
		return err
	}
	return Set(c)
}

// Load reads the config file, falling back to Default for any missing fields,
// and writes it back so that newly-added defaults are persisted.
func Load() (*Config, error) {
	conf := Default

	b, err := os.ReadFile(confPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &conf, Save(&conf)
		}
		return nil, fmt.Errorf("reading config: %v", err)
	}
	if err := json.Unmarshal(b, &conf); err != nil {
		return nil, fmt.Errorf("decoding config: %v", err)
	}
	// persist any new defaults in case the config structure changed
	return &conf, Save(&conf)
}

// Save writes conf to the config file with 0600 permissions.
func Save(conf *Config) error {
	mu.Lock()
	defer mu.Unlock()
	b, err := json.MarshalIndent(conf, "", "    ")
	if err != nil {
		return fmt.Errorf("encoding config: %v", err)
	}
	if err := os.WriteFile(confPath, b, 0600); err != nil {
		return fmt.Errorf("writing config: %v", err)
	}
	return nil
}

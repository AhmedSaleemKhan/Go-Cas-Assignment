package cas

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
)

type ContentAddressedStorage struct {
	Digests       map[string]string
	SyncMutex     sync.Mutex
	AllAlgorithms []string
	FileSize      map[string]int64
	WriteableDir  string
}

type MyContentAddressedStorageFileInfo struct {
	FileSize      int64
	Digests       string
	AlgorithmsCAS string
}

var (
	ErrToWriteDir    = errors.New("the diretory is not writable")
	ErrInvalidDigest = errors.New("invalid digest")
)

func (cas *ContentAddressedStorage) getHandlerFunc(path string) http.HandlerFunc {
	if strings.Contains(path, "/stats/") {
		return cas.ContentAddressedStorageStats
	} else {
		return cas.HandleGetFile
	}
}

func (cas *ContentAddressedStorage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		cas.ContentAddressedStorageFileUpload(w, r)

	case http.MethodGet:
		handlerFunc := cas.getHandlerFunc(r.URL.Path)
		handlerFunc(w, r)
	case http.MethodHead:
		cas.HandleGetFile(w, r)

	default:
		http.Error(w, "method isnt supported", http.StatusMethodNotAllowed)
	}
}

func CheckDirWritable(dir string) error {
	file, err := ioutil.TempFile(dir, "")
	if err != nil {
		return fmt.Errorf("failed to create file in directory: %w", ErrToWriteDir)
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()

	return nil
}

func CalculateHash(data []byte, hasher func() hash.Hash) string {
	h := hasher()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func getSupportedAlgorithms() map[string]bool {
	return map[string]bool{
		"sha256":     true,
		"sha384":     true,
		"sha512":     true,
		"sha512-224": true,
		"sha512-256": true,
	}
}

func (storage *ContentAddressedStorage) HandleGetFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path[len("/blob/"):]

	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	algo := parts[0]
	if !IsValidAlgorithm(algo, storage.AllAlgorithms) {
		http.Error(w, "Invalid algorithm", http.StatusBadRequest)
		return
	}

	digest := parts[1]
	if len(digest) == 0 {
		http.Error(w, "Digest required", http.StatusBadRequest)
		return
	}

	size, ok := storage.FileSize[digest]
	if !ok {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	info := MyContentAddressedStorageFileInfo{
		AlgorithmsCAS: algo,
		Digests:       digest,
		FileSize:      size,
	}

	resp, err := json.Marshal(info)
	if err != nil {
		http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	_, err = w.Write(resp)
	if err != nil {
		http.Error(w, "error: ", http.StatusInternalServerError)
		return
	}
}

func IsValidAlgorithm(algorithm string, supportedAlgorithms []string) bool {
	for _, alg := range supportedAlgorithms {
		if alg == algorithm {
			return true
		}
	}
	return false
}

func New(dir string, algorithms ...string) (*ContentAddressedStorage, error) {
	algorithmsSet, err := validateAlgorithms(algorithms)
	if err != nil {
		return nil, err
	}

	return &ContentAddressedStorage{
		WriteableDir:  dir,
		AllAlgorithms: algorithmsSet,
		FileSize:      make(map[string]int64),
		SyncMutex:     sync.Mutex{},
	}, nil
}

func validateAlgorithms(algorithms []string) ([]string, error) {
	Algorithms := getSupportedAlgorithms()
	algorithmsALL := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		if Algorithms[algorithm] {
			algorithmsALL = append(algorithmsALL, algorithm)
		} else {
			return nil, ErrInvalidDigest
		}
	}
	return algorithmsALL, nil
}

func GetSHA512_224Digest(data []byte) string {
	return CalculateHash(data, sha512.New512_224)
}

func GetSHA512_256Digest(data []byte) string {
	return CalculateHash(data, sha512.New512_256)
}

func (cas *ContentAddressedStorage) ContentAddressedStorageFileUpload(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	switch contentType {
	case "application/octet-stream":
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(data) == 0 {
			http.Error(w, "empty file", http.StatusBadRequest)
			return
		}
		size := int64(len(data))
		allHashes := make(map[string]string)
		for _, alg := range cas.AllAlgorithms {
			allDigest, err := cas.AlgorithmToHash(alg, data)
			if err != nil {
				http.Error(w, "cannot generate hash", http.StatusBadRequest)
				return
			}
			allHashes[alg] = allDigest
			cas.FileSize[allDigest] = size
			cas.Digests = allHashes
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-File-Size", fmt.Sprintf("%d", size))
		for algorithm, digest := range allHashes {
			key := fmt.Sprintf("X-Digest-%s", algorithm)
			w.Header().Set(key, digest)
		}
	default:
		http.Error(w, "invalid content type", http.StatusBadRequest)
	}
}

func (cas *ContentAddressedStorage) AlgorithmToHash(alg string, data []byte) (string, error) {
	funcs := map[string]func([]byte) string{
		"sha256":     GetSHA256Digest,
		"sha384":     GetSHA384Digest,
		"sha512":     GetSHA512Digest,
		"sha512-224": GetSHA512_224Digest,
		"sha512-256": GetSHA512_256Digest,
	}

	if allfuncs, check := funcs[alg]; check {
		return allfuncs(data), nil
	}
	return "", ErrInvalidDigest
}
func GetSHA256Digest(data []byte) string {
	return CalculateHash(data, sha256.New)
}

func GetSHA384Digest(data []byte) string {
	return CalculateHash(data, sha512.New384)
}

func GetSHA512Digest(data []byte) string {
	return CalculateHash(data, sha512.New)
}

type FileStats struct {
	MeanSize          float64 `json:"mean"`
	NumberOfFiles     int64   `json:"count"`
	StandardDeviation float64 `json:"stddev"`
}

func (cas *ContentAddressedStorage) ContentAddressedStorageStats(w http.ResponseWriter, r *http.Request) {

	var size, sizeSquare float64
	var noOfFiles int64

	cas.SyncMutex.Lock()
	defer cas.SyncMutex.Unlock()

	for _, sizeOfFile := range cas.FileSize {
		size += float64(sizeOfFile)
		sizeSquare += float64(sizeOfFile) * float64(sizeOfFile)
		noOfFiles++
	}

	if noOfFiles == 0 {
		http.Error(w, "No files in the ContentAddressedStorage", http.StatusNoContent)
		return
	}

	meanSize := size / float64(noOfFiles)
	stdDev := math.Sqrt((sizeSquare/float64(noOfFiles) - meanSize*meanSize))

	fileDetails := FileStats{
		NumberOfFiles:     noOfFiles / 2,
		MeanSize:          meanSize,
		StandardDeviation: stdDev,
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(fileDetails)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNoContent)
		return
	}
}

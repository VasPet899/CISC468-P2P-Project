package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/cisc468/p2p-project/internal/crypto"
	"github.com/cisc468/p2p-project/internal/storage"
)

// HandleListRequest returns a LIST_RESPONSE with all manifests from the file store.
func HandleListRequest(msg map[string]interface{}, fs *storage.FileStore, seq *int) (map[string]interface{}, error) {
	manifests, err := fs.ListManifests()
	if err != nil {
		return nil, err
	}
	files := make([]map[string]interface{}, 0, len(manifests))
	for _, m := range manifests {
		// Convert Manifest struct to map
		data, _ := json.Marshal(m)
		var mm map[string]interface{}
		json.Unmarshal(data, &mm)
		files = append(files, mm)
	}
	*seq++
	return ListResponse(*seq, files), nil
}

// BuildFileChunks creates TRANSFER_CHUNK and TRANSFER_COMPLETE messages for a file.
func BuildFileChunks(fs *storage.FileStore, fileID string, seqStart int) ([]map[string]interface{}, error) {
	fileData, err := fs.LoadFile(fileID)
	if err != nil {
		return nil, err
	}
	manifest, err := fs.LoadManifest(fileID)
	if err != nil {
		return nil, err
	}

	totalChunks := (len(fileData) + ChunkSize - 1) / ChunkSize
	if totalChunks == 0 {
		totalChunks = 1
	}

	var msgs []map[string]interface{}
	seq := seqStart

	for i := 0; i < totalChunks; i++ {
		start := i * ChunkSize
		end := start + ChunkSize
		if end > len(fileData) {
			end = len(fileData)
		}
		chunk := fileData[start:end]
		seq++
		msgs = append(msgs, TransferChunk(seq, fileID, i, totalChunks, chunk))
	}

	seq++
	msgs = append(msgs, TransferComplete(seq, fileID, manifest.SHA256))
	return msgs, nil
}

// ReassembleFile reassembles file data from TRANSFER_CHUNK messages.
func ReassembleFile(chunks []map[string]interface{}) ([]byte, error) {
	// Sort by chunk_index
	sort.Slice(chunks, func(i, j int) bool {
		ci, _ := chunks[i]["chunk_index"].(float64)
		cj, _ := chunks[j]["chunk_index"].(float64)
		return ci < cj
	})

	var data []byte
	for _, c := range chunks {
		chunkDataStr, _ := c["chunk_data"].(string)
		chunkData, err := crypto.B64URLDecode(chunkDataStr)
		if err != nil {
			return nil, fmt.Errorf("decode chunk data: %w", err)
		}
		data = append(data, chunkData...)
	}
	return data, nil
}

// VerifyReceivedFile verifies a received file's integrity and owner signature.
func VerifyReceivedFile(fileData []byte, manifest *storage.Manifest, ownerPKBytes []byte) error {
	if err := storage.VerifyFileIntegrity(fileData, manifest.SHA256); err != nil {
		return err
	}
	ownerPK, err := crypto.BytesToPublicKey(ownerPKBytes)
	if err != nil {
		return err
	}
	return storage.VerifyManifest(manifest, ed25519.PublicKey(ownerPK))
}

// Package protocol provides message types, handler dispatch, file operations,
// and key migration logic.
package protocol

import (
	"time"

	"github.com/cisc468/p2p-project/internal/crypto"
)

const (
	ProtocolVersion = "1"
	ChunkSize       = 64 * 1024 // 64 KB
)

// Error codes
const (
	AuthFailed       = "AUTH_FAILED"
	UnknownPeer      = "UNKNOWN_PEER"
	FileNotFound     = "FILE_NOT_FOUND"
	ConsentDenied    = "CONSENT_DENIED"
	IntegrityFailure = "INTEGRITY_FAILURE"
	MigrationInvalid = "MIGRATION_INVALID"
	ProtocolErrorCode = "PROTOCOL_ERROR"
	VersionMismatch  = "VERSION_MISMATCH"
)

func envelope(msgType string, seq int, extra map[string]interface{}) map[string]interface{} {
	msg := map[string]interface{}{
		"type":      msgType,
		"version":   ProtocolVersion,
		"seq":       float64(seq),
		"timestamp": float64(time.Now().UnixMilli()),
	}
	for k, v := range extra {
		msg[k] = v
	}
	return msg
}

func ListRequest(seq int, ownerID *string) map[string]interface{} {
	var oid interface{} = nil
	if ownerID != nil {
		oid = *ownerID
	}
	return envelope("LIST_REQUEST", seq, map[string]interface{}{
		"filter": map[string]interface{}{"owner_id": oid},
	})
}

func ListResponse(seq int, files []map[string]interface{}) map[string]interface{} {
	// Convert nil slice to empty array for JSON
	if files == nil {
		files = []map[string]interface{}{}
	}
	ifiles := make([]interface{}, len(files))
	for i, f := range files {
		ifiles[i] = f
	}
	return envelope("LIST_RESPONSE", seq, map[string]interface{}{
		"files": ifiles,
	})
}

func TransferRequest(seq int, fileID, requesterID string, manifest map[string]interface{}) map[string]interface{} {
	extra := map[string]interface{}{
		"file_id":      fileID,
		"requester_id": requesterID,
	}
	if manifest != nil {
		extra["manifest"] = manifest
	}
	return envelope("TRANSFER_REQUEST", seq, extra)
}

func TransferResponse(seq int, fileID string, accepted bool, reason string) map[string]interface{} {
	return envelope("TRANSFER_RESPONSE", seq, map[string]interface{}{
		"file_id":  fileID,
		"accepted": accepted,
		"reason":   reason,
	})
}

func TransferChunk(seq int, fileID string, chunkIndex, totalChunks int, chunkData []byte) map[string]interface{} {
	return envelope("TRANSFER_CHUNK", seq, map[string]interface{}{
		"file_id":      fileID,
		"chunk_index":  float64(chunkIndex),
		"total_chunks": float64(totalChunks),
		"chunk_data":   crypto.B64URLEncode(chunkData),
	})
}

func TransferComplete(seq int, fileID, sha256Hash string) map[string]interface{} {
	return envelope("TRANSFER_COMPLETE", seq, map[string]interface{}{
		"file_id": fileID,
		"sha256":  sha256Hash,
	})
}

func KeyMigration(seq int, oldPeerID, newPeerID string,
	effectiveTS, expiryTS int64, reason, oldSig, newSig string) map[string]interface{} {
	return envelope("KEY_MIGRATION", seq, map[string]interface{}{
		"old_peer_id":         oldPeerID,
		"new_peer_id":         newPeerID,
		"effective_timestamp": float64(effectiveTS),
		"expiry_timestamp":    float64(expiryTS),
		"reason":              reason,
		"old_signature":       oldSig,
		"new_signature":       newSig,
	})
}

func MigrationAck(seq int, accepted bool, reason string) map[string]interface{} {
	return envelope("MIGRATION_ACK", seq, map[string]interface{}{
		"accepted": accepted,
		"reason":   reason,
	})
}

func ErrorMsg(seq int, code, message string) map[string]interface{} {
	return envelope("ERROR", seq, map[string]interface{}{
		"code":    code,
		"message": message,
	})
}

package filesystem

import (
	"bytes"
	"encoding/binary"

	fieldparams "github.com/OffchainLabs/prysm/v7/config/fieldparams"
	"github.com/pkg/errors"
)

const (
	// blobSize is the fixed size of a blob field (131072 bytes)
	blobSize = fieldparams.BlobSize
	// compressionThreshold is the minimum trailing zeros to enable compression
	compressionThreshold = 1024 // 1KB minimum savings
)

// Custom compression magic bytes: "PRYS" (Prysm)
var compressionMagic = []byte{0x50, 0x52, 0x59, 0x53}

// compressedBlobHeaderSize is the size of the compression header:
// magic (4) + original_size (4) + data_length (4) + trailing_zero_count (4) = 16 bytes
const compressedBlobHeaderSize = 16

func isCompressed(data []byte) bool {
	if len(data) < len(compressionMagic) {
		return false
	}
	return bytes.HasPrefix(data, compressionMagic)
}

// findLastNonZero finds the index of the last non-zero byte
func findLastNonZero(blob []byte) int {
	for i := len(blob) - 1; i >= 0; i-- {
		if blob[i] != 0 {
			return i
		}
	}
	return -1 // All zeros
}

// compressBlobField compresses a blob field by removing trailing zeros
// Format: [magic: 4] [original_size: 4] [data_length: 4] [non_zero_data] [trailing_zero_count: 4]
// The result is padded to blobSize (131072) with zeros
func compressBlobField(blob []byte) ([]byte, error) {
	if len(blob) != blobSize {
		return nil, errors.Errorf("invalid blob size: expected %d, got %d", blobSize, len(blob))
	}

	// Find last non-zero byte
	lastNonZero := findLastNonZero(blob)
	if lastNonZero < 0 {
		// All zeros - store compressed format with zero data length
		compressed := make([]byte, blobSize)
		copy(compressed, compressionMagic)
		binary.BigEndian.PutUint32(compressed[4:8], uint32(blobSize))
		binary.BigEndian.PutUint32(compressed[8:12], 0)                 // data_length = 0
		binary.BigEndian.PutUint32(compressed[12:16], uint32(blobSize)) // trailing_zero_count = blobSize
		return compressed, nil
	}

	dataLength := lastNonZero + 1
	trailingZeros := blobSize - dataLength

	// Only compress if we save enough space
	if trailingZeros < compressionThreshold {
		return nil, nil // Signal: don't compress, not worth it
	}

	// Build compressed format: magic + sizes + data + zero count
	compressedSize := compressedBlobHeaderSize + dataLength
	if compressedSize > blobSize {
		return nil, errors.Errorf("compressed size %d exceeds blob size %d", compressedSize, blobSize)
	}

	compressed := make([]byte, blobSize) // Pad to blobSize with zeros
	copy(compressed, compressionMagic)
	binary.BigEndian.PutUint32(compressed[4:8], uint32(blobSize))
	binary.BigEndian.PutUint32(compressed[8:12], uint32(dataLength))
	copy(compressed[12:12+dataLength], blob[:dataLength])
	binary.BigEndian.PutUint32(compressed[12+dataLength:16+dataLength], uint32(trailingZeros))

	return compressed, nil
}

// compressBlobSSZ compresses the blob field in SSZ data if it has trailing zeros
// It modifies the blob field at offset 8:131080 in the SSZ data
func compressBlobSSZ(sszData []byte) ([]byte, error) {
	if len(sszData) != fieldparams.BlobSidecarSize {
		return sszData, nil // Not the expected size, skip compression
	}

	// Extract blob field from SSZ (bytes 8:131080)
	blobStart := 8
	blobEnd := 131080
	if len(sszData) < blobEnd {
		return sszData, nil
	}
	blob := sszData[blobStart:blobEnd]

	// Compress blob field
	compressedBlob, err := compressBlobField(blob)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compress blob field")
	}
	if compressedBlob == nil {
		// Not compressed (not enough trailing zeros)
		return sszData, nil
	}

	// Replace blob field in SSZ data
	result := make([]byte, len(sszData))
	copy(result, sszData)
	copy(result[blobStart:blobEnd], compressedBlob)

	return result, nil
}

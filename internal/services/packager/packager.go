package packager

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-json"
	"github.com/vayload/plug-registry/internal/domain"
	"github.com/vayload/plug-registry/internal/shared"
	"github.com/vayload/plug-registry/internal/shared/errors"
)

type PackageResult struct {
	Reader    io.Reader             // The .tar.gz file reader
	Metadata  domain.PluginManifest // manifest of plugin
	Manifest  string                // Raw JSON
	Readme    *string               // README content
	License   *string               // LICENSE content
	FileCount int                   // Number of files in the .tar.gz
	Checksum  func() [32]byte       // SHA256 final (called after consuming the Reader)
}

const (
	LimitFreeBytes       = 50 * 1024 * 1024  // 50 MB
	MaxFiles             = 250               // Support only 250 files max
	MaxSingleFileSize    = 5 * 1024 * 1024   // 5 MB
	MaxUncompressedTotal = 100 * 1024 * 1024 // 100 MB
)

type FileType int

const (
	Unknown FileType = iota
	TarGz
	Tgz
	Zip
	TarZst
	Tar
)

func (ft FileType) String() string {
	switch ft {
	case TarGz:
		return "tar.gz"
	case Tgz:
		return "tgz"
	case Zip:
		return "zip"
	case TarZst: // For future use
		return "tar.zst"
	default:
		return "unknown"
	}
}

var (
	gzipHeader = []byte{0x1F, 0x8B}
	zipHeader  = []byte{0x50, 0x4B, 0x03, 0x04}
	// zstdHeader = []byte{0x28, 0xB5, 0x2F, 0xFD} // TODO: Implement zstd support in the future
)

var (
	GZIP_MIME_TYPES = map[string]bool{
		"application/gzip":   true,
		"application/x-gzip": true,
		"application/x-tgz":  true,
	}
	ZIP_MIME_TYPES = map[string]bool{
		"application/zip":              true,
		"application/x-zip-compressed": true,
	}
	ZSTD_MIME_TYPES = map[string]bool{
		"application/zstd":   true,
		"application/x-zstd": true,
	}
	TAR_MIME_TYPES = map[string]bool{
		"application/x-tar": true,
	}
)

func contains(m map[string]bool, s string) bool {
	_, ok := m[s]
	return ok
}

// Detect based on magic bytes and filename extension
// gzip / tar.gz / tgz
// Mime type: application/gzip, application/x-gzip
// zip
// Mime type: application/zip, application/x-zip-compressed
// zstd / tar.zst
// Mime type: application/zstd, application/x-zstd
// tar
// Mime type: application/x-tar
func DetectFileType(reader io.Reader, filename, contentType string) (FileType, error) {
	buf := make([]byte, 4)
	n, err := reader.Read(buf)
	if err != nil {
		return Unknown, fmt.Errorf("failed to read file: %w", err)
	}

	// Seek to the beginning of the file, reset the reader for next operations
	if seeker, ok := reader.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	}

	contentType = strings.TrimSpace(strings.ToLower(contentType))
	switch {
	case n >= 2 && buf[0] == gzipHeader[0] && buf[1] == gzipHeader[1]:
		// gzip / tar.gz / tgz
		if strings.HasSuffix(filename, ".tar.gz") {
			if contentType != "" && !contains(GZIP_MIME_TYPES, contentType) {
				return TarGz, fmt.Errorf("content type %s does not match tar.gz", contentType)
			}
			return TarGz, nil
		}
		if strings.HasSuffix(filename, ".tgz") {
			return Tgz, nil
		}
		return Unknown, fmt.Errorf("filename %s does not match gzip content", filename)

	case n >= 4 && buf[0] == zipHeader[0] && buf[1] == zipHeader[1] && buf[2] == zipHeader[2] && buf[3] == zipHeader[3]:
		if strings.HasSuffix(filename, ".zip") {
			if contentType != "" && !contains(ZIP_MIME_TYPES, contentType) {
				return Zip, fmt.Errorf("content type %s does not match zip", contentType)
			}
			return Zip, nil
		}
		return Unknown, fmt.Errorf("filename %s does not match zip content", filename)

	// TODO: Implement zstd support is not in the roadmap for now
	// case n >= 4 && buf[0] == zstdHeader[0] && buf[1] == zstdHeader[1] && buf[2] == zstdHeader[2] && buf[3] == zstdHeader[3]:
	// 	if strings.HasSuffix(filename, ".zst") || strings.HasSuffix(filename, ".tar.zst") {
	// 		return TarZst, nil
	// 	}

	default:
		return Unknown, fmt.Errorf("unknown or unsupported file type")
	}
}

type defaultPackager struct{}

func NewDefaultPackager() *defaultPackager {
	return &defaultPackager{}
}

func (p *defaultPackager) Package(ctx context.Context, file *shared.File) (*PackageResult, error) {
	// Initial size check for the uploaded archive
	if file.Size > LimitFreeBytes {
		return nil, errors.BadRequest(fmt.Sprintf("archive too large: %d bytes", file.Size))
	}

	// Reset reader to the beginning for next operations
	if _, err := file.Reader.Seek(0, io.SeekStart); err != nil {
		return nil, errors.Internal("failed to reset reader").Cause(err)
	}

	fileType, err := DetectFileType(file.Reader, file.Filename, file.MimeType)
	if err != nil {
		return nil, errors.BadRequest(err.Error())
	}

	var (
		metadata                  domain.PluginManifest
		manifest, readme, license string
		isZip                     = (fileType == Zip)
		totalUncompressed         int64
		fileCount                 int
	)

	// Security Scan & Metadata Extraction
	if isZip {
		zr, err := zip.NewReader(&readSeekerAt{file.Reader}, file.Size)
		if err != nil {
			return nil, errors.BadRequest(fmt.Sprintf("invalid zip: %v", err))
		}

		if len(zr.File) > MaxFiles {
			return nil, errors.BadRequest("archive contains too many files")
		}

		for _, f := range zr.File {
			// SECURITY: Prevent Directory Traversal
			if err := isSafePath(f.Name); err != nil {
				return nil, errors.BadRequest(fmt.Sprintf("unsafe path in zip: %s", f.Name))
			}

			// SECURITY: Block Symlinks (check file mode bits)
			if f.Mode()&os.ModeSymlink != 0 {
				return nil, errors.BadRequest(fmt.Sprintf("symlinks are not allowed: %s", f.Name))
			}

			// ZIP BOMB PROTECTION: Check individual and total sizes
			totalUncompressed += int64(f.UncompressedSize64)
			if totalUncompressed > MaxUncompressedTotal {
				return nil, errors.BadRequest("total uncompressed size exceeds limit")
			}

			if !f.FileInfo().IsDir() {
				rc, err := f.Open()
				if err != nil {
					return nil, fmt.Errorf("failed to open file %s in zip: %w", f.Name, err)
				}

				defer rc.Close()

				p.extractFiles(f.Name, rc, &manifest, &readme, &license)
			}
		}
	} else {
		// TAR.GZ processing
		gzr, err := gzip.NewReader(file.Reader)
		if err != nil {
			return nil, errors.BadRequest("invalid tar.gz")
		}
		defer gzr.Close()
		tr := tar.NewReader(gzr)

		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}

			fileCount++
			if fileCount > MaxFiles {
				return nil, errors.BadRequest("too many files in archive")
			}

			// SECURITY: Prevent Directory Traversal
			if err := isSafePath(h.Name); err != nil {
				return nil, errors.BadRequest(fmt.Sprintf("unsafe path in tar: %s", h.Name))
			}

			// SECURITY: Only allow Regular Files (Blocks Symlinks, Devices, etc.)
			if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
				return nil, errors.BadRequest(fmt.Sprintf("unsupported file type in tar: %s", h.Name))
			}

			// ZIP BOMB PROTECTION
			totalUncompressed += h.Size
			if totalUncompressed > MaxUncompressedTotal {
				return nil, errors.BadRequest("total uncompressed size exceeds limit")
			}

			if h.Typeflag == tar.TypeReg {
				p.extractFiles(h.Name, tr, &manifest, &readme, &license)
			}
		}
	}

	// Validation
	if manifest == "" {
		return nil, errors.BadRequest("missing plugin.json")
	}
	if err := json.Unmarshal([]byte(string(manifest)), &metadata); err != nil {
		return nil, errors.BadRequest(fmt.Sprintf("invalid manifest format: %v", err))
	}

	// Final Stream Preparation
	if _, err := file.Reader.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	hasher := sha256.New()
	var finalReader io.Reader

	if isZip {
		// Convert ZIP to TAR.GZ on the fly
		pr, pw := io.Pipe()
		go func() {
			defer pw.Close()
			gzw := gzip.NewWriter(pw)
			defer gzw.Close()
			tw := tar.NewWriter(gzw)
			defer tw.Close()

			zr, _ := zip.NewReader(&readSeekerAt{file.Reader}, file.Size)
			for _, f := range zr.File {
				if f.FileInfo().IsDir() {
					continue
				}

				header, _ := tar.FileInfoHeader(f.FileInfo(), "")
				// Re-sanitize for the new header
				header.Name = filepath.ToSlash(filepath.Clean(f.Name))

				if err := tw.WriteHeader(header); err != nil {
					return
				}
				rc, _ := f.Open()
				io.Copy(tw, rc)
				rc.Close()
			}
		}()
		finalReader = io.TeeReader(pr, hasher)
	} else {
		finalReader = io.TeeReader(file.Reader, hasher)
	}

	return &PackageResult{
		Reader:    finalReader,
		Metadata:  metadata,
		Manifest:  manifest,
		Readme:    &readme,
		License:   &license,
		FileCount: fileCount,
		// Called when file is uploaded succesfully
		Checksum: func() [32]byte {
			var b [32]byte
			copy(b[:], hasher.Sum(nil))
			return b
		},
	}, nil
}

func (p *defaultPackager) extractFiles(name string, src io.Reader, manifest, readme, license *string) {
	lowerName := strings.ToLower(name)
	limitReader := io.LimitReader(src, 1*1024*1024)

	switch {
	case strings.HasSuffix(lowerName, "plugin.json"):
		buf, _ := io.ReadAll(limitReader)
		*manifest = string(buf)
	case strings.HasSuffix(lowerName, "readme.md"):
		buf, _ := io.ReadAll(limitReader)
		*readme = string(buf)
	case strings.HasSuffix(lowerName, "license") || strings.HasSuffix(lowerName, "license.md"):
		buf, _ := io.ReadAll(limitReader)
		*license = string(buf)
	}
}

// isSafePath checks for Directory Traversal attempts
func isSafePath(path string) error {
	// Clean the path (resolves ./ and ../)
	cleanPath := filepath.Clean(path)

	// Reject absolute paths or paths trying to go up levels
	if filepath.IsAbs(path) || strings.HasPrefix(cleanPath, "..") {
		return fmt.Errorf("path escapes sandbox")
	}
	return nil
}

type readSeekerAt struct {
	rs io.ReadSeeker
}

func (r *readSeekerAt) ReadAt(p []byte, off int64) (n int, err error) {
	if _, err := r.rs.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	return r.rs.Read(p)
}

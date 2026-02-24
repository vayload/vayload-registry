package services

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/vayload/plug-registry/internal/domain"
)

type defaultPackager struct{}

func NewDefaultPackager() IPluginPackager {
	return &defaultPackager{}
}

func (p *defaultPackager) Package(ctx context.Context, r io.Reader, size int64) (*IPackageResult, error) {
	rs, ok := r.(io.ReadSeeker)
	if !ok {
		return nil, fmt.Errorf("packager requires io.ReadSeeker")
	}

	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var metadata PluginMetadata
	var manifest, readme, license string
	var isZip bool

	header := make([]byte, 4)
	if _, err := io.ReadFull(rs, header); err == nil {
		if string(header) == "PK\x03\x04" {
			isZip = true
		}
	}
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	if isZip {
		zr, err := zip.NewReader(&readSeekerAt{rs}, size)
		if err != nil {
			return nil, domain.NewValidationError(fmt.Sprintf("Invalid zip format: %v", err))
		}

		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			name := strings.ToLower(f.Name)
			if name == "plugin.json" || name == "plugin.json5" || name == "readme.md" || name == "license.md" || name == "license" {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				buf := new(strings.Builder)
				if _, err := io.Copy(buf, io.LimitReader(rc, 1024*1024)); err == nil {
					content := buf.String()
					switch {
					case name == "plugin.json" || name == "plugin.json5":
						manifest = content
					case name == "readme.md":
						readme = content
					case name == "license.md" || name == "license":
						license = content
					}
				}
				rc.Close()
			}
		}
	} else {
		gzr, err := gzip.NewReader(rs)
		if err != nil {
			return nil, domain.NewValidationError("Invalid archive format (expected tar.gz or zip)")
		}
		tr := tar.NewReader(gzr)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			name := strings.ToLower(h.Name)
			if h.Typeflag == tar.TypeReg && (name == "plugin.json" || name == "plugin.json5" || name == "readme.md" || name == "license.md" || name == "license") {
				buf := new(strings.Builder)
				if _, err := io.Copy(buf, io.LimitReader(tr, 1024*1024)); err == nil {
					content := buf.String()
					switch {
					case name == "plugin.json" || name == "plugin.json5":
						manifest = content
					case name == "readme.md":
						readme = content
					case name == "license.md" || name == "license":
						license = content
					}
				}
			}
		}
		gzr.Close()
	}

	if manifest == "" {
		return nil, domain.NewValidationError("Missing plugin.json")
	}

	if err := json.Unmarshal([]byte(manifest), &metadata); err != nil {
		return nil, domain.NewValidationError(fmt.Sprintf("Invalid manifest: %v", err))
	}

	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var finalReader io.Reader
	hasher := sha256.New()

	if isZip {
		pr, pw := io.Pipe()
		go func() {
			defer pw.Close()
			gzw := gzip.NewWriter(pw)
			defer gzw.Close()
			tw := tar.NewWriter(gzw)
			defer tw.Close()

			zr, _ := zip.NewReader(&readSeekerAt{rs}, size)
			for _, f := range zr.File {
				if f.FileInfo().IsDir() {
					continue
				}
				header, _ := tar.FileInfoHeader(f.FileInfo(), "")
				header.Name = f.Name
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
		finalReader = io.TeeReader(rs, hasher)
	}

	return &IPackageResult{
		Reader:   finalReader,
		Metadata: metadata,
		Manifest: manifest,
		Readme:   &readme,
		License:  &license,
		Checksum: func() string {
			return fmt.Sprintf("%x", hasher.Sum(nil))
		},
	}, nil
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

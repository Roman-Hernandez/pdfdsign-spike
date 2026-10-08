package verification

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pkcs7"
)

type revision struct {
	leaf       *x509.Certificate
	end        int64
	validRange bool
}

type scan struct {
	revisions         []revision
	permission        int
	restrictedFields  bool
	unsupportedFilter bool
	size              int64
}

// SigningPolicy reports restrictions without treating an unsigned PDF as an error.
func SigningPolicy(path string) (count, permission int, restricted bool, err error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, false, err
	}
	defer file.Close()
	data, err := scanRevisions(file)
	if err != nil {
		return 0, 0, false, err
	}
	return len(data.revisions), data.permission, data.restrictedFields || data.unsupportedFilter, nil
}

// scanRevisions shares the PDF traversal used for CMS identity and revision bounds.
func scanRevisions(file *os.File) (data scan, err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("signature inspection failed: %v", value)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return data, err
	}
	data.size = info.Size()
	reader, err := pdf.NewReader(file, data.size)
	if err != nil {
		return data, err
	}
	catalog := reader.Trailer().Key("Root")
	certification := catalog.Key("Perms").Key("DocMDP")
	if !certification.IsNull() {
		data.permission = 1
	}
	for _, xref := range reader.Xref() {
		value := reader.Resolve(xref.Ptr(), xref.Ptr())
		if value.Key("Type").Name() != "Sig" && value.Key("Filter").Name() != "Adobe.PPKLite" && (value.Key("ByteRange").IsNull() || value.Key("Contents").IsNull()) {
			continue
		}
		if value.Key("Contents").IsNull() || value.Key("ByteRange").IsNull() {
			data.revisions = append(data.revisions, revision{})
			continue
		}
		if value.Key("Filter").Name() != "Adobe.PPKLite" {
			data.unsupportedFilter = true
		}
		refs := value.Key("Reference")
		for j := 0; j < refs.Len(); j++ {
			ref := refs.Index(j)
			switch ref.Key("TransformMethod").Name() {
			case "DocMDP":
				p := int(ref.Key("TransformParams").Key("P").Int64())
				if p < 1 || p > 3 {
					p = 1
				}
				data.permission = p
			case "FieldMDP":
				data.restrictedFields = true
			}
		}
		item := revision{}
		ranges := value.Key("ByteRange")
		if ranges.Len() == 4 {
			a, b, c, d := ranges.Index(0).Int64(), ranges.Index(1).Int64(), ranges.Index(2).Int64(), ranges.Index(3).Int64()
			item.validRange = a == 0 && b >= 0 && b < c && c <= data.size && d >= 0 && d <= data.size-c
			if item.validRange {
				item.end = c + d
			}
		}
		if cms, parseErr := pkcs7.Parse([]byte(value.Key("Contents").RawString())); parseErr == nil {
			item.leaf = cms.GetOnlySigner()
		}
		data.revisions = append(data.revisions, item)
	}
	return data, nil
}

// comparePrefix confirms that appending a signature did not rewrite earlier bytes.
func PreservesOriginal(original, signed string) (bool, error) {
	before, err := os.Open(original)
	if err != nil {
		return false, err
	}
	defer before.Close()
	after, err := os.Open(signed)
	if err != nil {
		return false, err
	}
	defer after.Close()
	a, b := make([]byte, 32*1024), make([]byte, 32*1024)
	for {
		n, readErr := before.Read(a)
		if n > 0 {
			if _, err := io.ReadFull(after, b[:n]); err != nil {
				return false, err
			}
			for i := 0; i < n; i++ {
				if a[i] != b[i] {
					return false, nil
				}
			}
		}
		if readErr == io.EOF {
			return true, nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}

// Package release builds the manifest that lets a CubeCOS node decide whether
// the agent binary it is about to run is the one Bigstack released.
//
// The format is dictated by where it gets checked. The verifier lives in
// cubecos, not here — a verifier must not share a build pipeline with the
// artifact it verifies, or one compromised pipeline defeats both (ADR 0003) —
// and it is plain shell, small enough that a reviewer can read all of it:
//
//	openssl dgst -sha256 -verify release.pub -signature manifest.sig manifest.txt
//	sha256sum -c manifest.txt
//
// So the manifest is exactly what sha256sum already understands, with metadata
// carried in comment lines that sha256sum ignores. Nothing on the verifying
// side parses a bespoke format, because a bespoke parser in shell is where the
// bugs would be.
package release

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Artifact is one released file.
type Artifact struct {
	Name   string // base name as published, e.g. cube-advisor-agent_linux_amd64
	SHA256 string // lowercase hex
	Size   int64
}

// Manifest describes one release.
type Manifest struct {
	Version         string // release version, e.g. 0.2.0
	Commit          string // git commit the artifacts were built from
	ProtocolVersion int    // tunnel protocol this agent speaks
	Artifacts       []Artifact
}

// Metadata keys, written as sha256sum comments. Kept short and greppable
// because an operator reading a manifest on a console is a supported use.
const (
	keyVersion  = "version"
	keyCommit   = "commit"
	keyProtocol = "protocol"
)

// Render writes the manifest in sha256sum's own format.
//
// Comment lines (leading '#') carry the metadata; sha256sum -c skips them, so
// the same bytes are both a machine-checkable digest list and a human-readable
// record of what this release is. Artifacts are sorted so the same inputs
// always produce byte-identical output — a manifest that varies run to run
// cannot be reproduced by anyone checking our work.
func (m Manifest) Render() []byte {
	arts := append([]Artifact(nil), m.Artifacts...)
	sort.Slice(arts, func(i, j int) bool { return arts[i].Name < arts[j].Name })

	var b strings.Builder
	fmt.Fprintf(&b, "# cube-advisor-agent release manifest\n")
	fmt.Fprintf(&b, "# %s: %s\n", keyVersion, m.Version)
	fmt.Fprintf(&b, "# %s: %s\n", keyCommit, m.Commit)
	fmt.Fprintf(&b, "# %s: %d\n", keyProtocol, m.ProtocolVersion)
	for _, a := range arts {
		// Two spaces then the name: sha256sum's binary-mode format.
		fmt.Fprintf(&b, "%s  %s\n", a.SHA256, a.Name)
	}
	return []byte(b.String())
}

// ParseManifest reads a rendered manifest back.
//
// Used by the SaaS when serving a release and by tests; the node-side verifier
// deliberately does not parse it at all.
func ParseManifest(r io.Reader) (Manifest, error) {
	var m Manifest
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			k, v, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "#")), ":")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case keyVersion:
				m.Version = v
			case keyCommit:
				m.Commit = v
			case keyProtocol:
				if _, err := fmt.Sscanf(v, "%d", &m.ProtocolVersion); err != nil {
					return Manifest{}, fmt.Errorf("release: bad protocol version %q", v)
				}
			}
			continue
		}
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			return Manifest{}, fmt.Errorf("release: unparseable line %q", line)
		}
		if len(sum) != 64 {
			return Manifest{}, fmt.Errorf("release: %q is not a sha256 digest", sum)
		}
		m.Artifacts = append(m.Artifacts, Artifact{Name: name, SHA256: sum})
	}
	if err := sc.Err(); err != nil {
		return Manifest{}, err
	}
	if len(m.Artifacts) == 0 {
		return Manifest{}, fmt.Errorf("release: manifest lists no artifacts")
	}
	return m, nil
}

// Build produces a manifest for every regular file in dir.
//
// Directories are walked rather than globbed so a release cannot silently omit
// an architecture because someone forgot to extend a pattern.
func Build(dir, version, commit string, protocolVersion int) (Manifest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Manifest{}, fmt.Errorf("release: read %s: %w", dir, err)
	}
	m := Manifest{Version: version, Commit: commit, ProtocolVersion: protocolVersion}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Never digest the manifest or its signature into itself.
		if e.Name() == ManifestName || e.Name() == SignatureName {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return Manifest{}, err
		}
		sum, err := fileSHA256(filepath.Join(dir, e.Name()))
		if err != nil {
			return Manifest{}, err
		}
		m.Artifacts = append(m.Artifacts, Artifact{Name: e.Name(), SHA256: sum, Size: info.Size()})
	}
	if len(m.Artifacts) == 0 {
		return Manifest{}, fmt.Errorf("release: no artifacts in %s", dir)
	}
	return m, nil
}

// Names of the files a release publishes alongside its artifacts.
const (
	ManifestName  = "manifest.txt"
	SignatureName = "manifest.txt.sig"
)

// WriteManifest renders m into dir.
func WriteManifest(dir string, m Manifest) error {
	return os.WriteFile(filepath.Join(dir, ManifestName), m.Render(), 0o644)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

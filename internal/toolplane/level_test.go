package toolplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLevel(t *testing.T, dir, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, LevelFileName), []byte(body), mode); err != nil {
		t.Fatalf("write level file: %v", err)
	}
}

// The three shapes of "nobody said" all answer observe, and none of them is an
// error: an agent on a cluster that has never configured a level is a normal
// agent, not a broken one.
func TestNoLevelRecordedServesReadsOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(dir string)
	}{
		{"no file at all", func(string) {}},
		{"an empty file", func(dir string) { writeLevel(t, dir, "", 0o644) }},
		{"a file of whitespace", func(dir string) { writeLevel(t, dir, "  \n\t\n", 0o644) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.write(dir)

			got, err := ReadLevel(dir)
			if err != nil {
				t.Errorf("ReadLevel errored on %s: %v", tc.name, err)
			}
			if got != DefaultLevel {
				t.Errorf("ReadLevel = %v, want %v", got, DefaultLevel)
			}
		})
	}
}

func TestARecordedLevelIsRead(t *testing.T) {
	for _, l := range []Level{LevelObserve, LevelOperate, LevelInternal} {
		dir := t.TempDir()
		// Trailing newline on purpose: every editor and every `echo` writes
		// one, so a parser that cannot survive it would fail on almost every
		// real file.
		writeLevel(t, dir, l.String()+"\n", 0o644)

		got, err := ReadLevel(dir)
		if err != nil {
			t.Errorf("ReadLevel(%q) errored: %v", l, err)
			continue
		}
		if got != l {
			t.Errorf("ReadLevel = %v, want %v", got, l)
		}
	}
}

// The loud case, and the one that matters most. Someone wrote a word meaning
// something; it is not being honoured; the cluster is serving less than its
// operator believes. Silence here is the failure a level exists to prevent, so
// the error must name the file, the value and the vocabulary — an error that
// says only "invalid" sends an operator to read the source.
func TestAnUnreadableLevelIsLoudAndStillFailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeLevel(t, dir, "operator\n", 0o644)

	got, err := ReadLevel(dir)
	if err == nil {
		t.Fatal("ReadLevel accepted a word that is not a level")
	}
	if got != DefaultLevel {
		t.Errorf("ReadLevel = %v alongside the error, want the fail-closed %v", got, DefaultLevel)
	}
	for _, want := range []string{LevelFileName, "operator", "observe", "operate", "internal"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// A control any local account can raise is not a control. Readability is
// deliberately allowed — the level is a policy statement the customer should be
// able to inspect — so only the write bits are refused.
func TestALevelFileOthersCanWriteIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o666, 0o664, 0o622} {
		dir := t.TempDir()
		writeLevel(t, dir, "internal\n", mode)
		if err := os.Chmod(filepath.Join(dir, LevelFileName), mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}

		got, err := ReadLevel(dir)
		if err == nil {
			t.Errorf("mode %04o was accepted; a writable level file is not a control", mode)
		}
		if got != DefaultLevel {
			t.Errorf("mode %04o: ReadLevel = %v, want %v", mode, got, DefaultLevel)
		}
	}

	// World-readable is fine, and must stay fine: refusing it would push
	// operators toward 0600 on a file that is not a secret, and make
	// inspecting your own cluster's policy need root.
	dir := t.TempDir()
	writeLevel(t, dir, "operate\n", 0o644)
	if got, err := ReadLevel(dir); err != nil || got != LevelOperate {
		t.Errorf("ReadLevel on a 0644 file = %v, %v; want operate and no error", got, err)
	}
}

func TestEveryLevelRoundTripsThroughItsRecordedWord(t *testing.T) {
	for _, l := range []Level{LevelObserve, LevelOperate, LevelInternal} {
		got, err := ParseLevel(l.String())
		if err != nil || got != l {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v and no error", l.String(), got, err, l)
		}
	}
}

// The whole mapping, written out rather than derived, because deriving it is
// the mistake: the classes ascend read(1) scratch(2) operate(3) internal(4), so
// `impact <= level` would serve probes to a cluster that asked for operations.
// A probe plane is a property of this agent's build, never of a level.
func TestEachLevelServesTheClassesItNames(t *testing.T) {
	for _, tc := range []struct {
		level  Level
		serves map[Impact]bool
	}{
		{LevelObserve, map[Impact]bool{
			ImpactRead: true, ImpactScratch: false, ImpactOperate: false, ImpactInternal: false,
		}},
		{LevelOperate, map[Impact]bool{
			ImpactRead: true, ImpactScratch: false, ImpactOperate: true, ImpactInternal: false,
		}},
		{LevelInternal, map[Impact]bool{
			ImpactRead: true, ImpactScratch: false, ImpactOperate: true, ImpactInternal: true,
		}},
	} {
		for impact, want := range tc.serves {
			if got := tc.level.Serves(impact); got != want {
				t.Errorf("%v.Serves(%v) = %v, want %v", tc.level, impact, got, want)
			}
		}
	}
}

func TestAnUnrecognisedLevelServesNothing(t *testing.T) {
	for _, bad := range []Level{0, LevelInternal + 1} {
		for _, i := range []Impact{ImpactRead, ImpactScratch, ImpactOperate, ImpactInternal} {
			if bad.Serves(i) {
				t.Errorf("level %d served impact %v; absence of a rule is not permission", bad, i)
			}
		}
	}
}

// The vocabulary is kept in step with cube-ai-advisor internal/actionlevel by
// hand — nothing carries a level across the wire, so there is no contract to
// check against, only two lists that must say the same words. Pinning the words
// here means a rename on this side fails a test rather than drifting quietly.
func TestTheRecordedWordsAreTheOnesTheSaaSWrites(t *testing.T) {
	want := map[Level]string{
		LevelObserve:  "observe",
		LevelOperate:  "operate",
		LevelInternal: "internal",
	}
	for l, w := range want {
		if l.String() != w {
			t.Errorf("Level(%d).String() = %q, want %q — cube-ai-advisor internal/actionlevel writes this word", int(l), l.String(), w)
		}
	}
}

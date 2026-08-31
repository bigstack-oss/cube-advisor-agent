package main

import (
	"os"
	"path/filepath"
	"testing"
)

func withEnvFile(t *testing.T, contents string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "phone-home-agent.env")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	old := phoneHomeEnv
	phoneHomeEnv = path
	t.Cleanup(func() { phoneHomeEnv = old })
}

func TestClusterIDFromDriver(t *testing.T) {
	for _, tc := range []struct {
		name     string
		contents string
		want     string
	}{
		{
			name:     "the value the driver writes",
			contents: "CUBE_CLUSTER_ID=ky3haclust01\n",
			want:     "ky3haclust01",
		},
		{
			name:     "beside other variables",
			contents: "CUBE_SITE=lab\nCUBE_CLUSTER_ID=ky3haclust01\nCUBE_TOKEN=xyz\n",
			want:     "ky3haclust01",
		},
		{
			name:     "quoted",
			contents: "CUBE_CLUSTER_ID=\"ky3haclust01\"\n",
			want:     "ky3haclust01",
		},
		{
			name:     "exported",
			contents: "export CUBE_CLUSTER_ID=ky3haclust01\n",
			want:     "ky3haclust01",
		},
		{
			name:     "commented out is absent",
			contents: "#CUBE_CLUSTER_ID=ky3haclust01\n",
			want:     "",
		},
		{
			name:     "a similarly named variable is not it",
			contents: "CUBE_CLUSTER_IDENTITY=nope\n",
			want:     "",
		},
		{
			name:     "empty file",
			contents: "",
			want:     "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withEnvFile(t, tc.contents)
			if got := clusterIDFromDriver(); got != tc.want {
				t.Fatalf("clusterIDFromDriver() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClusterIDFromDriverOnAHandBuiltCluster covers the fallback path: no such
// file, no error, and the caller goes on to the hostname.
func TestClusterIDFromDriverOnAHandBuiltCluster(t *testing.T) {
	old := phoneHomeEnv
	phoneHomeEnv = filepath.Join(t.TempDir(), "does-not-exist.env")
	t.Cleanup(func() { phoneHomeEnv = old })

	if got := clusterIDFromDriver(); got != "" {
		t.Fatalf("clusterIDFromDriver() with no file = %q, want empty", got)
	}
}

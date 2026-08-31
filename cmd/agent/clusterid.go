package main

import (
	"bufio"
	"os"
	"strings"
)

// phoneHomeEnv is where a driver-deployed cluster records the identity the
// driver assigned it. Overridable so tests never read the real file.
var phoneHomeEnv = "/etc/cube/phone-home-agent.env"

// clusterIDKey is the variable the driver writes there.
const clusterIDKey = "CUBE_CLUSTER_ID"

// clusterIDFromDriver returns the cluster id the driver assigned this cluster,
// or "" when this is not a driver-deployed cluster.
//
// Why prefer it over the hostname: a cluster id is a one-way door. It becomes
// the CommonName of the certificate the tunnel admits on, and five tables in
// the SaaS reference it without ON UPDATE CASCADE, so renaming means
// re-enrolling. The driver's value is derived from the cluster UUID and so is
// unique by construction, where a hostname is unique only by luck — two
// customers can each have a `controller`, and the SaaS primary key is global.
//
// Absence is not an error. A hand-built cluster has no such file, and the
// caller falls back to what it knows.
func clusterIDFromDriver() string {
	f, err := os.Open(phoneHomeEnv)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) != clusterIDKey {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return ""
}

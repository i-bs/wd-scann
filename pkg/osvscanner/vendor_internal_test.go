package osvscanner

import (
	"net/url"
	"strings"
	"testing"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/osvdata"
	"github.com/google/osv-scalibr/plugin"
)

func TestVulnMatchFailure(t *testing.T) {
	t.Parallel()

	// the plugin's failure reason: the module's canonical warning, then the download error
	unavailable := (&osvdata.UnavailableError{
		Family: osvinternal.EcosystemJDK, Reason: "HTTP 404",
		URL: osvdata.DefaultProductBaseURL + "/" + url.PathEscape(osvinternal.EcosystemJDK) + "/all.zip",
	}).Warning() + ": unable to fetch OSV database: db host returned 404 Not Found"
	failed := func(name, reason string) *plugin.Status {
		return &plugin.Status{Name: name, Status: &plugin.ScanStatus{Status: plugin.ScanStatusFailed, FailureReason: reason}}
	}

	tests := []struct {
		name    string
		status  *plugin.Status
		actions ScannerActions
		wantErr bool
	}{
		{"succeeded plugin", &plugin.Status{Name: "vulnmatch/osvlocal", Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}}, ScannerActions{CompareOffline: true}, false},
		{"another plugin", failed("os/apk", "boom"), ScannerActions{CompareOffline: true}, false},
		{"cached offline, database missing", failed("vulnmatch/osvlocal", "no offline version of the OSV database is available"), ScannerActions{CompareOffline: true}, true},
		{"offline with downloads, download failed", failed("vulnmatch/osvlocal", "db host returned 404 Not Found"), ScannerActions{CompareOffline: true, DownloadDatabases: true}, false},
		{"online, generic failure", failed("vulnmatch/osvlocal", "db host returned 404 Not Found"), ScannerActions{}, false},
		{"online, vendor database unavailable, strict", failed("vulnmatch/osvlocal", unavailable), ScannerActions{VendorStrict: true}, true},
		{"offline with downloads, vendor database unavailable, strict", failed("vulnmatch/osvlocal", unavailable), ScannerActions{CompareOffline: true, DownloadDatabases: true, VendorStrict: true}, true},
		{"strict, failure of another kind", failed("vulnmatch/osvlocal", "db host returned 404 Not Found"), ScannerActions{VendorStrict: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := vulnMatchFailure(tt.status, tt.actions); (err != nil) != tt.wantErr {
				t.Errorf("vulnMatchFailure() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckVendorOptions(t *testing.T) {
	t.Parallel()

	if err := checkVendorOptions(ScannerActions{VendorFeeds: []string{osvinternal.EcosystemJDK + "=https://example.com/osv", strings.ToLower(osvinternal.EcosystemLinux) + "=/srv/osv"}}); err != nil {
		t.Errorf("checkVendorOptions() = %v, want nil", err)
	}
	for _, bad := range []string{osvinternal.EcosystemJDK, "Zulu=https://example.com/osv"} {
		if err := checkVendorOptions(ScannerActions{VendorFeeds: []string{bad}}); err == nil {
			t.Errorf("checkVendorOptions(%q) = nil, want an error", bad)
		}
	}
}

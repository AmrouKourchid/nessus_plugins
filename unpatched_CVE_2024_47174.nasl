#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229606);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-47174");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-47174");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - Nix is a package manager for Linux and other Unix systems. Starting in version 1.11 and prior to versions
    2.18.8 and 2.24.8, `<nix/fetchurl.nix>` did not verify TLS certificates on HTTPS connections. This could
    lead to connection details such as full URLs or credentials leaking in case of a man-in-the-middle (MITM)
    attack. `<nix/fetchurl.nix>` is also known as the builtin derivation builder `builtin:fetchurl`. It's not
    to be confused with the evaluation-time function `builtins.fetchurl`, which was not affected by this
    issue. A user may be affected by the risk of leaking credentials if they have a `netrc` file for
    authentication, or rely on derivations with `impureEnvVars` set to use credentials from the environment.
    In addition, the commonplace trust-on-first-use (TOFU) technique of updating dependencies by specifying an
    invalid hash and obtaining it from a remote store was also vulnerable to a MITM injecting arbitrary store
    objects. This also applied to the impure derivations experimental feature. Note that this may also happen
    when using Nixpkgs fetchers to obtain new hashes when not using the fake hash method, although that
    mechanism is not implemented in Nix itself but rather in Nixpkgs using a fixed-output derivation. The
    behavior was introduced in version 1.11 to make it consistent with the Nixpkgs `pkgs.fetchurl` and to make
    `<nix/fetchurl.nix>` work in the derivation builder sandbox, which back then did not have access to the CA
    bundles by default. Nowadays, CA bundles are bind-mounted on Linux. This issue has been fixed in Nix
    2.18.8 and 2.24.8. As a workaround, implement (authenticated) fetching with `pkgs.fetchurl` from Nixpkgs,
    using `impureEnvVars` and `curlOpts` as needed. (CVE-2024-47174)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47174");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "nix-bin",
     "nix-setup-systemd"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match_one": {
        "os_version": [
         "11",
         "12"
        ]
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);

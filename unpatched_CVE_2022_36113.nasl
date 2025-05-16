#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224865);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-36113");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-36113");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - Cargo is a package manager for the rust programming language. After a package is downloaded, Cargo
    extracts its source code in the ~/.cargo folder on disk, making it available to the Rust projects it
    builds. To record when an extraction is successful, Cargo writes ok to the .cargo-ok file at the root of
    the extracted source code once it extracted all the files. It was discovered that Cargo allowed packages
    to contain a .cargo-ok symbolic link, which Cargo would extract. Then, when Cargo attempted to write ok
    into .cargo-ok, it would actually replace the first two bytes of the file the symlink pointed to with ok.
    This would allow an attacker to corrupt one file on the machine using Cargo to extract the package. Note
    that by design Cargo allows code execution at build time, due to build scripts and procedural macros. The
    vulnerabilities in this advisory allow performing a subset of the possible damage in a harder to track
    down way. Your dependencies must still be trusted if you want to be protected from attacks, as it's
    possible to perform the same attacks with build scripts and procedural macros. The vulnerability is
    present in all versions of Cargo. Rust 1.64, to be released on September 22nd, will include a fix for it.
    Since the vulnerability is just a more limited way to accomplish what a malicious build scripts or
    procedural macros can do, we decided not to publish Rust point releases backporting the security fix.
    Patch files are available for Rust 1.63.0 are available in the wg-security-response repository for people
    building their own toolchain. Mitigations We recommend users of alternate registries to exercise care in
    which package they download, by only including trusted dependencies in their projects. Please note that
    even with these vulnerabilities fixed, by design Cargo allows arbitrary code execution at build time
    thanks to build scripts and procedural macros: a malicious dependency will be able to cause damage
    regardless of these vulnerabilities. crates.io implemented server-side checks to reject these kinds of
    packages years ago, and there are no packages on crates.io exploiting these vulnerabilities. crates.io
    users still need to exercise care in choosing their dependencies though, as remote code execution is
    allowed by design there as well. (CVE-2022-36113)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36113");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
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
     "cargo",
     "cargo-doc",
     "librust-cargo+openssl-dev",
     "librust-cargo-dev"
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
       "match": {
        "os_version": "11"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);

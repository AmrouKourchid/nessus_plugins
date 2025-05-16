#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227307);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-42503");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-42503");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - Improper Input Validation, Uncontrolled Resource Consumption vulnerability in Apache Commons Compress in
    TAR parsing.This issue affects Apache Commons Compress: from 1.22 before 1.24.0. Users are recommended to
    upgrade to version 1.24.0, which fixes the issue. A third party can create a malformed TAR file by
    manipulating file modification times headers, which when parsed with Apache Commons Compress, will cause a
    denial of service issue via CPU consumption. In version 1.22 of Apache Commons Compress, support was added
    for file modification times with higher precision (issue # COMPRESS-612 [1]). The format for the PAX
    extended headers carrying this data consists of two numbers separated by a period [2], indicating seconds
    and subsecond precision (for example 1647221103.5998539). The impacted fields are atime, ctime,
    mtime and LIBARCHIVE.creationtime. No input validation is performed prior to the parsing of header
    values. Parsing of these numbers uses the BigDecimal [3] class from the JDK which has a publicly known
    algorithmic complexity issue when doing operations on large numbers, causing denial of service (see issue
    # JDK-6560193 [4]). A third party can manipulate file time headers in a TAR file by placing a number with
    a very long fraction (300,000 digits) or a number with exponent notation (such as 9e9999999) within a
    file modification time header, and the parsing of files with these headers will take hours instead of
    seconds, leading to a denial of service via exhaustion of CPU resources. This issue is similar to
    CVE-2012-2098 [5]. [1]: https://issues.apache.org/jira/browse/COMPRESS-612 [2]:
    https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html#tag_20_92_13_05 [3]:
    https://docs.oracle.com/javase/8/docs/api/java/math/BigDecimal.html [4]:
    https://bugs.openjdk.org/browse/JDK-6560193 [5]: https://cve.mitre.org/cgi-
    bin/cvename.cgi?name=CVE-2012-2098 Only applications using CompressorStreamFactory class (with auto-
    detection of file types), TarArchiveInputStream and TarFile classes to parse TAR files are impacted. Since
    this code was introduced in v1.22, only that version and later versions are impacted. (CVE-2023-42503)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/14");
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
    "name": "libcommons-compress-java",
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
        "os_version": "12"
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

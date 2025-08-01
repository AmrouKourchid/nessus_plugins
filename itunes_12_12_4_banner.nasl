##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161375);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/25");

  script_cve_id(
    "CVE-2022-26711",
    "CVE-2022-26717",
    "CVE-2022-26751",
    "CVE-2022-26773",
    "CVE-2022-26774",
    "CVE-2022-48611"
  );
  script_xref(name:"APPLE-SA", value:"HT213259");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2022-05-18");

  script_name(english:"Apple iTunes < 12.12.4 Multiple Vulnerabilities (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is prior to 12.12.4. It is, therefore, affected by
multiple vulnerabilities as referenced in the HT213259 advisory.

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in iTunes
    12.12.4 for Windows, iOS 15.5 and iPadOS 15.5, Security Update 2022-004 Catalina, macOS Big Sur 11.6.6,
    macOS Monterey 12.4. Processing a maliciously crafted image may lead to arbitrary code execution.
    (CVE-2022-26751)

  - An integer overflow issue was addressed with improved input validation. This issue is fixed in tvOS 15.5,
    iTunes 12.12.4 for Windows, iOS 15.5 and iPadOS 15.5, watchOS 8.6, macOS Monterey 12.4. A remote attacker
    may be able to cause unexpected application termination or arbitrary code execution. (CVE-2022-26711)

  - A logic issue was addressed with improved state management. This issue is fixed in iTunes 12.12.4 for
    Windows. A local attacker may be able to elevate their privileges. (CVE-2022-26774)

  - A logic issue was addressed with improved state management. This issue is fixed in iTunes 12.12.4 for
    Windows. An application may be able to delete files for which it does not have permission.
    (CVE-2022-26773)

  - A use after free issue was addressed with improved memory management. This issue is fixed in tvOS 15.5,
    watchOS 8.6, iOS 15.5 and iPadOS 15.5, macOS Monterey 12.4, Safari 15.5, iTunes 12.12.4 for Windows.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-26717)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213259");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.12.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("installed_sw/iTunes DAAP");
  script_require_ports("Services/www", 3689);

  exit(0);
}
include('http.inc');
include('vcf.inc');

var app = 'iTunes DAAP';
var port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

var app_info = vcf::get_app_info(app:app, port:port);
if (app_info.Type != 'Windows') audit(AUDIT_OS_NOT, 'Windows');
var constraints = [{'fixed_version':'12.12.4'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

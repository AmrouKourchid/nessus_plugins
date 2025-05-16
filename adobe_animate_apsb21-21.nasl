##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147748);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-21071",
    "CVE-2021-21072",
    "CVE-2021-21073",
    "CVE-2021-21074",
    "CVE-2021-21075",
    "CVE-2021-21076",
    "CVE-2021-21077"
  );
  script_xref(name:"IAVA", value:"2021-A-0122-S");

  script_name(english:"Adobe Animate 20.x < 20.5.2 / 21.x < 21.0.4 Multiple Vulnerabilities (APSB21-21)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Animate installed on remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Animate installed on the remote Windows host is prior to 20.5.2 or 21.0.4. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb21-21 advisory.

  - Adobe Animate version 21.0.3 (and earlier) is affected by a Heap-based Buffer Overflow vulnerability. An
    unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-21077)

  - Adobe Animate version 21.0.3 (and earlier) is affected by an Out-of-bounds Read vulnerability. An
    unauthenticated attacker could leverage this vulnerability to disclose sensitive information in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-21072, CVE-2021-21073, CVE-2021-21074, CVE-2021-21075, CVE-2021-21076)

  - Adobe Animate version 21.0.3 (and earlier) is affected by a Memory Corruption vulnerability. An
    unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-21071)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/animate/apsb21-21.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Animate version 20.5.2 or 21.0.4 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21077");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21072");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:animate");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_animate_installed.nbin");
  script_require_keys("installed_sw/Adobe Animate", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Animate', win_local:TRUE);

var constraints = [
  { 'min_version' : '20.0.0', 'fixed_version' : '20.5.2' },
  { 'min_version' : '21.0.0', 'fixed_version' : '21.0.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);

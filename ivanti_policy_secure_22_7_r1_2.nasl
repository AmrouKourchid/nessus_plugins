#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211467);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id(
    "CVE-2024-8495",
    "CVE-2024-9420",
    "CVE-2024-11004",
    "CVE-2024-11005",
    "CVE-2024-11006",
    "CVE-2024-11007",
    "CVE-2024-11634",
    "CVE-2024-38655",
    "CVE-2024-38656",
    "CVE-2024-39709",
    "CVE-2024-39710",
    "CVE-2024-39711",
    "CVE-2024-39712",
    "CVE-2024-47905",
    "CVE-2024-47906",
    "CVE-2024-47909"
  );
  script_xref(name:"IAVA", value:"2024-A-0800-S");

  script_name(english:"Ivanti Policy Secure 22.7R1.2 (Build 1485) Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Policy Secure installed on the remote host is prior to 22.7R1.2 (Build 1485). It is, therefore,
affected by multiple vulnerabilities as referenced in the CVE-2024-11005 advisory.

  - A null pointer dereference in Ivanti Connect Secure before version 22.7R2.1 and Ivanti Policy Secure
    before version 22.7R1.1 allows a remote unauthenticated attacker to cause a denial of service.
    (CVE-2024-8495)

  - A use-after-free in Ivanti Connect Secure before version 22.7R2.3 and Ivanti Policy Secure before version
    22.7R1.2 allows a remote authenticated attacker to achieve remote code execution. (CVE-2024-9420)

  - Reflected XSS in Ivanti Connect Secure before version 22.7R2.1 and Ivanti Policy Secure before version
    22.7R1.1 allows a remote unauthenticated attacker to obtain admin privileges. User interaction is
    required. (CVE-2024-11004)

  - Command injection in Ivanti Connect Secure before version 22.7R2.1 and Ivanti Policy Secure before version
    22.7R1.1 allows a remote authenticated attacker with admin privileges to achieve remote code execution.
    (CVE-2024-11005, CVE-2024-11006, CVE-2024-11007)

  - Argument injection in Ivanti Connect Secure before version 22.7R2.1 and Ivanti Policy Secure before
    version 22.7R1.1 allows a remote authenticated attacker with admin privileges to achieve remote code
    execution. (CVE-2024-38655)

  - Argument injection in Ivanti Connect Secure before version 22.7R2.2 and 9.1R18.9 and Ivanti Policy Secure
    before version 22.7R1.2 allows a remote authenticated attacker with admin privileges to achieve remote
    code execution. (CVE-2024-38656)

  - Incorrect file permissions in Ivanti Connect Secure before version 22.6R2 and Ivanti Policy Secure before
    version 22.6R1 allow a local authenticated attacker to escalate their privileges. (CVE-2024-39709)

  - Argument injection in Ivanti Connect Secure before version 22.7R2 and 9.1R18.7 and Ivanti Policy Secure
    before version 22.7R1.1 allows a remote authenticated attacker with admin privileges to achieve remote
    code execution. (CVE-2024-39710)

  - Argument injection in Ivanti Connect Secure before version 22.7R2.1 and 9.1R18.7 and Ivanti Policy Secure
    before version 22.7R1.1 allows a remote authenticated attacker with admin privileges to achieve remote
    code execution. (CVE-2024-39711, CVE-2024-39712)

  - A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.3 and Ivanti Policy Secure
    before version 22.7R1.2 allows a remote authenticated attacker with admin privileges to cause a denial of
    service. (CVE-2024-47905, CVE-2024-47909)

  - Excessive binary privileges in Ivanti Connect Secure which affects versions 22.4R2 through 22.7R2.2
    inclusive within the R2 release line and Ivanti Policy Secure before version 22.7R1.2 allow a local
    authenticated attacker to escalate privileges. (CVE-2024-47906)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-ICS-Ivanti-Policy-Secure-IPS-Ivanti-Secure-Access-Client-ISAC-Multiple-CVEs?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7626e0b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Policy Secure version 22.7R1.2 (Build 1485) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9420");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulse_secure:pulse_policy_secure");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:policy_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_policy_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Policy Secure");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Pulse Policy Secure');

var constraints = [
  { 'fixed_version' : '22.7.1.1485', 'fixed_display' : '22.7R1.2 (Build 1485)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);

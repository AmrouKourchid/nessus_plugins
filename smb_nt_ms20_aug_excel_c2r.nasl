#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('compat.inc');

if (description)
{
  script_id(162053);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id(
    "CVE-2020-1494",
    "CVE-2020-1495",
    "CVE-2020-1496",
    "CVE-2020-1497",
    "CVE-2020-1498",
    "CVE-2020-1504"
  );
  script_xref(name:"IAVA", value:"2020-A-0365-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");

  script_name(english:"Security Updates for Microsoft Excel Products C2R (August 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2020-1497)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2020-1494, CVE-2020-1495,
    CVE-2020-1496, CVE-2020-1498, CVE-2020-1504)");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1504");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1498");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS20-08';

var constraints = [
    {'fixed_version':'16.0.11328.20644','channel': 'Deferred'},
    {'fixed_version':'16.0.11929.20934','channel': 'Deferred','channel_version': '1908'},
    {'fixed_version':'16.0.13001.20520','channel': 'Enterprise Deferred','channel_version': '2006'},
    {'fixed_version':'16.0.12827.20656','channel': 'Enterprise Deferred'},
    {'fixed_version':'16.0.12527.20988','channel': 'Microsoft 365 Apps on Windows 7'},
    {'fixed_version':'16.0.12527.20988','channel': 'First Release for Deferred'},
    {'fixed_version':'16.0.13029.20344','channel': '2016 Retail'},
    {'fixed_version':'16.0.13029.20344','channel': 'Current'},
    {'fixed_version':'16.0.12527.20988','channel': '2019 Retail'},
    {'fixed_version':'16.0.12527.20988','channel': '2019 Retail','channel_version': '2002'},
    {'fixed_version':'16.0.13029.20344','channel': '2019 Retail','channel_version': '2004'},
    {'fixed_version':'16.0.10364.20059','channel': '2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Excel'
);
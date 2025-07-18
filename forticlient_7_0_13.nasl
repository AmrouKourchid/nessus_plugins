#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(213441);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id("CVE-2024-50570");

  script_name(english:"Fortinet FortiClient 7.0.x < 7.0.14 / 7.2.x < 7.2.7 / 7.4.x < 7.4.2 Information Disclosure (FG-IR-23-278)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiClient running on the remote host is prior to 7.0.14, 7.2.7, or 7.4.2. It is, therefore,
affected by a an information disclosure vulnerability due to the use of a hard-coded cryptographic key to encrypt
security sensitive data in configuration. An attacker with access to the configuration or the backup file may
exploit this in order to decrypt the sensitive data via knowledge of the hard-coded key.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-278");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 7.0.14, 7.2.7, 7.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50570");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(312);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('installed_sw/FortiClient');
app_info = vcf::get_app_info(app:'FortiClient');

constraints = [
  {'min_version' : '7.0', 'fixed_version' : '7.0.14'},
  {'min_version' : '7.2', 'fixed_version' : '7.2.7'},
  {'min_version' : '7.4', 'fixed_version' : '7.4.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

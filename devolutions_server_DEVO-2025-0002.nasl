#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216583);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id("CVE-2025-1231");
  script_xref(name:"IAVB", value:"2025-B-0026-S");

  script_name(english:"Devolutions Server < 2024.3.11.0 Improper Password Reset (DEVO-2025-0002)");

  script_set_attribute(attribute:"synopsis", value:
"The Devolutions Server instance installed on the remote host is affected by an improper pasword reset vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Devolutions Server installed on the remote host is prior to 2024.3.11.0 and is, therefore, affected by
an improper password reset vulnerability:

  - Improper password reset in PAM Module in Devolutions Server 2024.3.10.0 and earlier allows an authenticated user to
    reuse the oracle user password after check-in due to crash in the password reset functionality. (CVE-2025-1231)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://devolutions.net/security/advisories/DEVO-2025-0002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Devolutions Server version 2024.3.11.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1231");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:devolutions:remote_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("devolutions_server_win_installed.nbin");
  script_require_keys("installed_sw/Devolutions Server", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Devolutions Server', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '2024.3.11.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);

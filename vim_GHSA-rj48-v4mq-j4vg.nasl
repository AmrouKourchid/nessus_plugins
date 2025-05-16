#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208441);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-47814");
  script_xref(name:"IAVA", value:"2024-A-0618-S");

  script_name(english:"Vim 9.1.0764 (GHSA-rj48-v4mq-j4vg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Vim installed on the remote host is prior to 9.1.0764. It is, therefore, affected by a vulnerability as
referenced in the GHSA-rj48-v4mq-j4vg advisory.

  - Vim is an open source, command line text editor. A use-after-free was found in Vim < 9.1.0764. When
    closing a buffer (visible in a window) a BufWinLeave auto command can cause an use-after-free if this auto
    command happens to re-open the same buffer in a new split window. Impact is low since the user must have
    intentionally set up such a strange auto command and run some buffer unload commands. However this may
    lead to a crash. This issue has been addressed in version 9.1.0764 and all users are advised to upgrade.
    There are no known workarounds for this vulnerability. (CVE-2024-47814)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vim/vim/security/advisories/GHSA-rj48-v4mq-j4vg");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.1.0764 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47814");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Vim', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.1.0764' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_NOTE
);

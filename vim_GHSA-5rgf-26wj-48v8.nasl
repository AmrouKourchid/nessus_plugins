#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214215);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2025-22134");
  script_xref(name:"IAVA", value:"2025-A-0020-S");

  script_name(english:"Vim 9.1.1003 (GHSA-5rgf-26wj-48v8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Vim installed on the remote host is prior to 9.1.1003. It is, therefore, affected by a vulnerability as
referenced in the GHSA-5rgf-26wj-48v8 advisory.

  - When switching to other buffers using the :all command and visual mode still being active, this may cause
    a heap-buffer overflow, because Vim does not properly end visual mode and therefore may try to access
    beyond the end of a line in a buffer. In Patch 9.1.1003 Vim will correctly reset the visual mode before
    opening other windows and buffers and therefore fix this bug. In addition it does verify that it won't try
    to access a position if the position is greater than the corresponding buffer line. Impact is medium since
    the user must have switched on visual mode when executing the :all ex command. The Vim project would like
    to thank github user gandalf4a for reporting this issue. The issue has been fixed as of Vim patch
    v9.1.1003 (CVE-2025-22134)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vim/vim/security/advisories/GHSA-5rgf-26wj-48v8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.1.1003 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22134");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Vim', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.1.1003' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_NOTE
);

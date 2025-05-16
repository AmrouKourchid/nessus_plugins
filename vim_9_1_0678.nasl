#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206156);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id("CVE-2024-43374");
  script_xref(name:"IAVA", value:"2024-A-0505-S");

  script_name(english:"Vim < 9.1.0678 Heap-Use");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Vim installed on the remote host is prior to 9.1.0678. It is, therefore, affected by a vulnerability as
referenced in the advisory.

  - The UNIX editor Vim prior to version 9.1.0678 has a use-after-free error in argument list handling. When
    adding a new file to the argument list, this triggers `Buf*` autocommands. If in such an autocommand the
    buffer that was just opened is closed (including the window where it is shown), this causes the window
    structure to be freed which contains a reference to the argument list that we are actually modifying. Once
    the autocommands are completed, the references to the window and argument list are no longer valid and as
    such cause an use-after-free. Impact is low since the user must either intentionally add some unusual
    autocommands that wipe a buffer during creation (either manually or by sourcing a malicious plugin), but
    it will crash Vim. The issue has been fixed as of Vim patch v9.1.0678. (CVE-2024-43374)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vim/vim/security/advisories/GHSA-2w8m-443v-cgvw");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.1.0678 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Vim', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.1.0678' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_NOTE
);

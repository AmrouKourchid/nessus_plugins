#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205386);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/13");

  script_cve_id("CVE-2024-41965");

  script_name(english:"Vim < 9.1.0648 Double-Free");

  script_set_attribute(attribute:"synopsis", value:
"A text editor installed on the remote Windows host is affected a double-free vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the version of Vim installed on the remote Windows host is prior to 9.1.0648. It is, 
therefore affected by a double free vulnerability. When abandoning a buffer, Vim may ask the user what to do with the 
modified buffer. If the user wants the changed buffer to be saved, Vim may create a new Untitled file, if the buffer 
did not have a name yet. However, when setting the buffer name to Unnamed, Vim will falsely free a pointer twice, 
leading to a double-free and possibly later to a heap-use-after-free, which can lead to a crash.  

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/vim/vim/security/advisories/GHSA-46pw-v7qw-xc2f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a012e08c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.1.0648 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41965");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Vim', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.1.0648' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

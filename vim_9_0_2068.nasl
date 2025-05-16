#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184197);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/08");

  script_cve_id("CVE-2023-46246");
  script_xref(name:"IAVA", value:"2023-A-0598-S");

  script_name(english:"Vim < 9.0.2068 Use After Free");

  script_set_attribute(attribute:"synopsis", value:
"A text editor installed on the remote Windows host is affected a use after free vulnerability.");
  script_set_attribute(attribute:"description", value:
"Vim is an improved version of the good old UNIX editor Vi. Heap-use-after-free in memory allocated in the function
`ga_grow_inner` in in the file `src/alloc.c` at line 748, which is freed in the file `src/ex_docmd.c` in the function
`do_cmdline` at line 1010 and then used again in `src/cmdhist.c` at line 759. When using the `:history` command,
it's possible that the provided argument overflows the accepted value. Causing an Integer Overflow and potentially
later an use-after-free.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vim/vim/security/advisories/GHSA-q22m-h7m2-9mgm");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.0.2068 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46246");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Vim', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.0.2068' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

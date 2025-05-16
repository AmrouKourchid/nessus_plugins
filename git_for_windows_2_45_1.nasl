#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202262);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/15");

  script_cve_id(
    "CVE-2024-32002",
    "CVE-2024-32004",
    "CVE-2024-32020",
    "CVE-2024-32021",
    "CVE-2024-32465"
  );

  script_name(english:"Git for Windows < 2.45.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a Github for Windows install that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Git for Windows installed on the remote host is prior to 2.45.1, 
and therefore is affected by multiple vulnerabilities:

  - Recursive clones on case-insensitive filesystems that 
    support symbolic links are susceptible to case confusion 
    that can be exploited to execute just-cloned code during 
    the clone operation. (CVE-2024-32002)

  - Repositories can be configured to execute arbitrary code 
    during local clones. To address this, the ownership 
    checks introduced in v2.30.3 are now extended to cover 
    cloning local repositories. (CVE-2024-32004)

  - Local clones may end up hardlinking files into the target
    repository's object database when source and target 
    repository reside on the same disk. If the source 
    repository is owned by a different user, then those
    hardlinked files may be rewritten at any point in time 
    by the untrusted user. (CVE-2024-32020)

  - When cloning a local source repository that contains 
    symlinks via the filesystem, Git may create hardlinks 
    to arbitrary user-readable files on the same filesystem 
    as the target repository in the objects/ directory. 
    (CVE-2024-32021)

  - It is supposed to be safe to clone untrusted repositories,
    even those unpacked from zip archives or tarballs 
    originating from untrusted sources, but Git can be tricked 
    to run arbitrary code as part of the clone.(CVE-2024-32465)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/git-for-windows/git/releases/");
  # https://github.com/git-for-windows/git/releases/tag/v2.45.1.windows.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed7b9e75");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Git for Windows 2.45.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:git_for_windows_project:git_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("git_for_windows_installed.nbin");
  script_require_keys("installed_sw/Git for Windows");

  exit(0);
}

include('vcf.inc');

var app_name = 'Git for Windows';

var app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '2.45.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

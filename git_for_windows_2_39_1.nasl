#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184470);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id("CVE-2022-23521", "CVE-2022-41903");

  script_name(english:"Git for Windows < 2.30.7 / 2.31.6 / 2.32.5 / 2.33.6 / 2.34.6 / 2.35.6 / 2.36.4 / 2.37.5 / 2.38.3 / 2.39.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Git for Windows installed on the remote host is affect by multiple vulnerabilities, as follows:

  - Git is distributed revision control system. gitattributes are a mechanism to allow defining attributes for
    paths. These attributes can be defined by adding a .gitattributes file to the repository, which contains a
    set of file patterns and the attributes that should be set for paths matching this pattern. When parsing
    gitattributes, multiple integer overflows can occur when there is a huge number of path patterns, a huge
    number of attributes for a single pattern, or when the declared attribute names are huge. These overflows
    can be triggered via a crafted `.gitattributes` file that may be part of the commit history. Git silently
    splits lines longer than 2KB when parsing gitattributes from a file, but not when parsing them from the
    index. Consequentially, the failure mode depends on whether the file exists in the working tree, the index
    or both. This integer overflow can result in arbitrary heap reads and writes, which may result in remote
    code execution. The problem has been patched in the versions published on 2023-01-17, going back to
    v2.30.7. Users are advised to upgrade. There are no known workarounds for this issue. (CVE-2022-23521)

  - Git is distributed revision control system. `git log` can display commits in an arbitrary format using its
    --format specifiers. This functionality is also exposed to git archive via the export-subst gitattribute.
    When processing the padding operators, there is a integer overflow in pretty.c::format_and_pad_commit()
    where a size_t is stored improperly as an int, and then added as an offset to a memcpy(). This overflow
    can be triggered directly by a user running a command which invokes the commit formatting machinery (e.g.,
    git log --format=...). It may also be triggered indirectly through git archive via the export-subst
    mechanism, which expands format specifiers inside of files within the repository during a git archive.
    This integer overflow can result in arbitrary heap writes, which may result in arbitrary code execution.
    The problem has been patched in the versions published on 2023-01-17, going back to v2.30.7. Users are
    advised to upgrade. Users who are unable to upgrade should disable git archive in untrusted repositories.
    If you expose git archive via git daemon, disable it by running git config --global daemon.uploadArch
    false. (CVE-2022-41903)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/git/git/security/advisories/GHSA-c738-c5qq-xg89");
  script_set_attribute(attribute:"see_also", value:"https://github.com/git/git/security/advisories/GHSA-475x-2q3q-hvwq");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Git for Windows 2.30.7, 2.31.6, 2.32.5, 2.33.6, 2.34.6, 2.35.6, 2.36.4, 2.37.5, 2.38.3, 2.39.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:git_for_windows_project:git_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("git_for_windows_installed.nbin");
  script_require_keys("installed_sw/Git for Windows");

  exit(0);
}

include('vcf.inc');

var app_name = 'Git for Windows';

var app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '2.30.7' },
  { 'equal' : '2.31.5', 'fixed_display' : '2.31.6' },
  { 'equal' : '2.32.4', 'fixed_display' : '2.32.5' },
  { 'equal' : '2.33.5', 'fixed_display' : '2.33.6' },
  { 'equal' : '2.34.5', 'fixed_display' : '2.34.6' },
  { 'equal' : '2.35.5', 'fixed_display' : '2.35.6' },
  { 'equal' : '2.36.3', 'fixed_display' : '2.36.4' },
  { 'equal' : '2.37.4', 'fixed_display' : '2.37.5' },
  { 'equal' : '2.38.2', 'fixed_display' : '2.38.3' },
  { 'equal' : '2.39.0', 'fixed_display' : '2.39.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

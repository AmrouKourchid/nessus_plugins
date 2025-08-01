#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# Portions Copyright (C) 1996-2019, The PostgreSQL Global Development Group
# Portions Copyright (C) 1994, The Regents of the University of California
# Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee, and without a written agreement is hereby granted, provided that the above copyright notice and this paragraph and the following two paragraphs appear in all copies.
# IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
##

include('compat.inc');

if (description)
{
  script_id(179922);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2023-39417", "CVE-2023-39418");
  script_xref(name:"IAVB", value:"2023-B-0060-S");

  script_name(english:"PostgreSQL 11.x < 11.21 / 12.x < 12.16 / 13.x < 13.12 / 14.x < 14.9 / 15.x < 15.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 11 prior to 11.21, 12 prior to 12.16, 13 prior to 13.12, 14
prior to 14.9, or 15 prior to 15.4. As such, it is potentially affected by a vulnerability :

  - An extension script is vulnerable if it uses @extowner@, @extschema@, or @extschema:...@ inside a quoting
    construct (dollar quoting, '', or ). No bundled extension is vulnerable. Vulnerable uses do appear in a
    documentation example and in non-bundled extensions. Hence, the attack prerequisite is an administrator having
    installed files of a vulnerable, trusted, non-bundled extension. Subject to that prerequisite, this enables an
    attacker having database-level CREATE privilege to execute arbitrary code as the bootstrap superuser. PostgreSQL
    will block this attack in the core server, so there's no need to modify individual extensions. (CVE-2023-39417)

  - A vulnerability was found in PostgreSQL with the use of the MERGE command, which fails to test new rows against row
    security policies defined for UPDATE and SELECT. If UPDATE and SELECT policies forbid some rows that INSERT policies
    do not forbid, a user could store such rows. (CVE-2023-39418)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.postgresql.org/about/news/postgresql-154-149-1312-1216-1121-and-postgresql-16-beta-3-released-2689/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88535bbe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 11.21 / 12.16 / 13.12 / 14.9 / 15.4 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39417");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgres_installed_windows.nbin", "postgres_installed_nix.nbin", "postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('backport.inc');

var port = get_service(svc:'postgresql', default:5432, exit_on_fail:TRUE);
var kb_base = 'database/' + port + '/postgresql/';

var kb_ver = kb_base + 'version';
get_kb_item_or_exit(kb_ver);

var kb_backport = NULL;
var source = get_kb_item_or_exit(kb_base + 'source');
get_backport_banner(banner:source);
if (backported) kb_backport = kb_base + 'backported';

var app_info = vcf::get_app_info(app:'PostgreSQL', port:port, kb_ver:kb_ver, kb_backport:kb_backport, service:TRUE);

#  11.21 / 12.16 / 13.12 / 14.9 / 15.4
var constraints = [
  { 'min_version' : '11', 'fixed_version' : '11.21' },
  { 'min_version' : '12', 'fixed_version' : '12.16' },
  { 'min_version' : '13', 'fixed_version' : '13.12' },
  { 'min_version' : '14', 'fixed_version' : '14.9' },
  { 'min_version' : '15', 'fixed_version' : '15.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{'sqli':TRUE});

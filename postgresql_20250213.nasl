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
  script_id(216586);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id("CVE-2025-1094");
  script_xref(name:"IAVB", value:"2025-B-0028");

  script_name(english:"PostgreSQL 13.x < 13.19 / 14.x < 14.16 / 15.x < 15.11 / 16.x < 16.7 / 17.x < 17.3 SQLi");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 13 prior to 13.19, 14 prior to 14.16, 15 prior to 15.11, 16
prior to 16.7, or 17 prior to 17.3. As such, it is potentially affected by a vulnerability :

  - Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(),
    PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to
    achieve SQL injection in certain usage patterns. Specifically, SQL injection requires the application to
    use the function result to construct input to psql, the PostgreSQL interactive terminal. Similarly,
    improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of
    command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of
    EUC_TW or MULE_INTERNAL. Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.
    (CVE-2025-1094)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.postgresql.org/about/news/postgresql-173-167-1511-1416-and-1319-released-3015/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a3cbcdf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 13.19 / 14.16 / 15.11 / 16.7 / 17.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1094");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'BeyondTrust Privileged Remote Access (PRA) and Remote Support (RS) unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgres_installed_windows.nbin", "postgres_installed_nix.nbin", "postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432, "installed_sw/PostgreSQL", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_postgresql.inc');

var app = 'PostgreSQL';
var win_local = TRUE;

if (!get_kb_item('SMB/Registry/Enumerated'))
  win_local = FALSE;

var port = get_service(svc:'postgresql', default:5432);
var kb_base = 'database/' + port + '/postgresql/';
var kb_ver = NULL;
var kb_path = kb_base + 'version';
var ver = get_kb_item(kb_path);
if (!empty_or_null(ver)) kb_ver = kb_path;

var app_info = vcf::postgresql::get_app_info(app:app, port:port, kb_ver:kb_ver, kb_base:kb_base, win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '13.0', 'fixed_version' : '13.19' },
  { 'min_version' : '14.0', 'fixed_version' : '14.16' },
  { 'min_version' : '15.0', 'fixed_version' : '15.11' },
  { 'min_version' : '16.0', 'fixed_version' : '16.7' },
  { 'min_version' : '17.0', 'fixed_version' : '17.3' }
];

vcf::postgresql::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);

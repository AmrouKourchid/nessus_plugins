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
  script_id(161801);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2022-1552");
  script_xref(name:"IAVB", value:"2022-B-0015-S");

  script_name(english:"PostgreSQL 10.x < 10.21 / 11.x < 11.16 / 12.x < 12.11 / 13.x < 13.7 / 14.x < 14.3 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 10 prior to 10.21, 11 prior to 11.16, 12 prior to 12.11, 13
prior to 13.7, or 14 prior to 14.3. As such, it is potentially affected by a privilege escalation vulnerability:

  - Autovacuum, REINDEX, CREATE INDEX, REFRESH MATERIALIZED VIEW, CLUSTER, and pg_amcheck made incomplete efforts to
    operate safely when a privileged user is maintaining another user's objects. Those commands activated relevant
    protections too late or not at all. An attacker having permission to create non-temp objects in at least one schema
    could execute arbitrary SQL functions under a superuser identity. (CVE-2022-1552)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.postgresql.org/about/news/postgresql-143-137-1211-1116-and-1021-released-2449/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62f9afbd");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/support/security/CVE-2022-1552/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 10.21 / 11.16 / 12.11 / 13.7 / 14.3 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1552");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgres_installed_windows.nbin", "postgres_installed_nix.nbin", "postgresql_version.nbin");
  script_require_keys("installed_sw/PostgreSQL", "Settings/ParanoidReport");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include('vcf_extras_postgresql.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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

#  10.21 / 11.16 / 12.11 / 13.7 / 14.3
var constraints = [
  { 'min_version' : '10', 'fixed_version' : '10.21' },
  { 'min_version' : '11', 'fixed_version' : '11.16' },
  { 'min_version' : '12', 'fixed_version' : '12.11' },
  { 'min_version' : '13', 'fixed_version' : '13.7' },
  { 'min_version' : '14', 'fixed_version' : '14.3' }
];

vcf::postgresql::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

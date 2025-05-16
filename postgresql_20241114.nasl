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
  script_id(211655);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id(
    "CVE-2024-10976",
    "CVE-2024-10977",
    "CVE-2024-10978",
    "CVE-2024-10979"
  );
  script_xref(name:"IAVB", value:"2024-B-0175-S");

  script_name(english:"PostgreSQL 12.x < 12.21 / 13.x < 13.17 / 14.x < 14.14 / 15.x < 15.9 / 16.x < 16.5 / 17.x < 17.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 12 prior to 12.21, 13 prior to 13.17, 14 prior to 14.14, 15 
prior to 15.9, 16 prior to 16.5, or 17 prior to 17.1. As such, it is potentially affected by multiple vulnerabilities :

  - Incorrect control of environment variables in PostgreSQL PL/Perl allows an unprivileged database user to
    change sensitive process environment variables (e.g. PATH). That often suffices to enable arbitrary code
    execution, even if the attacker lacks a database server operating system user. (CVE-2024-10979)

  - Incorrect privilege assignment in PostgreSQL allows a less-privileged application user to view or change
    different rows from those intended. An attack requires the application to use SET ROLE, SET SESSION
    AUTHORIZATION, or an equivalent feature. The problem arises when an application query uses parameters from
    the attacker or conveys query results to the attacker. If that query reacts to current_setting('role') or
    the current user ID, it may modify or return data as though the session had not used SET ROLE or SET
    SESSION AUTHORIZATION. The attacker does not control which incorrect user ID applies. Query text from
    less-privileged sources is not a concern here, because SET ROLE and SET SESSION AUTHORIZATION are not
    sandboxes for unvetted queries. (CVE-2024-10978)

  - Client use of server error message in PostgreSQL allows a server not trusted under current SSL or GSS
    settings to furnish arbitrary non-NUL bytes to the libpq application. For example, a man-in-the-middle
    attacker could send a long error message that a human or screen-scraper user of psql mistakes for valid
    query results. This is probably not a concern for clients where the user interface unambiguously indicates
    the boundary between one error message and other text. (CVE-2024-10977)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.postgresql.org/about/news/postgresql-171-165-159-1414-1317-and-1221-released-2955/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9644dd1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 13.17 / 14.14 / 15.9 / 16.5 / 17.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10979");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

#  12.21 / 13.17 / 14.14 / 15.9 / 16.5 / 17.1
var constraints = [
  { 'min_version' : '12', 'fixed_version' : '12.21', 'fixed_display' : '12.x is now End Of Life (EOL) and is vulnerable. Contact the vendor.'},
  { 'min_version' : '13', 'fixed_version' : '13.17' },
  { 'min_version' : '14', 'fixed_version' : '14.14' },
  { 'min_version' : '15', 'fixed_version' : '15.9' },
  { 'min_version' : '16', 'fixed_version' : '16.5' },
  { 'min_version' : '17', 'fixed_version' : '17.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202724);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/23");

  script_cve_id(
    "CVE-2022-41881",
    "CVE-2022-41915",
    "CVE-2024-0397",
    "CVE-2024-2511",
    "CVE-2024-4603",
    "CVE-2024-4741",
    "CVE-2024-21098",
    "CVE-2024-21123",
    "CVE-2024-21126",
    "CVE-2024-21174",
    "CVE-2024-21184"
  );

  script_name(english:"Oracle Database Server (Jul 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the July 2024 CPU advisory.

  - Netty project is an event-driven asynchronous network application framework. In versions prior to
    4.1.86.Final, a StackOverflowError can be raised when parsing a malformed crafted message due to an
    infinite recursion. This issue is patched in version 4.1.86.Final. There is no workaround, except using a
    custom HaProxyMessageDecoder. (CVE-2022-41881)

  - Netty project is an event-driven asynchronous network application framework. Starting in version
    4.1.83.Final and prior to 4.1.86.Final, when calling `DefaultHttpHeadesr.set` with an _iterator_ of
    values, header value validation was not performed, allowing malicious header values in the iterator to
    perform HTTP Response Splitting. This issue has been patched in version 4.1.86.Final. Integrators can work
    around the issue by changing the `DefaultHttpHeaders.set(CharSequence, Iterator<?>)` call, into a
    `remove()` call, and call `add()` in a loop over the iterator of values. (CVE-2022-41915)

  - A defect was discovered in the Python ssl module where there is a memory race condition with the
    ssl.SSLContext methods cert_store_stats() and get_ca_certs(). The race condition can be triggered if
    the methods are called at the same time as certificates are loaded into the SSLContext, such as during the
    TLS handshake with a certificate directory configured. This issue is fixed in CPython 3.10.14, 3.11.9,
    3.12.3, and 3.13.0a5. (CVE-2024-0397)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21184");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  { 'min_version' : '19.0', 'max_version' : '19.24' },
  { 'min_version' : '21.0', 'max_version' : '21.14' }
];

var constraints = [
  # RDBMS:
  {'min_version': '21.0', 'fixed_version': '21.15.0.0.240716', 'missing_patch':'36521898', 'os':'win', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.15.0.0.240716', 'missing_patch':'36696242', 'os':'unix', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.24.0.0.240716', 'missing_patch':'36521936', 'os':'win', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.24.0.0.240716', 'missing_patch':'36582781', 'os':'unix', 'component':'db'},

  {'min_version': '19.0',  'fixed_version': '19.24.0.0.240716', 'missing_patch':'36414915', 'os':'win', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.24.0.0.240716', 'missing_patch':'36414915', 'os':'unix', 'component':'ojvm'}

];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

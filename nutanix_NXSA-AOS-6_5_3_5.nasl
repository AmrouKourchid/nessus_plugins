#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178057);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2023-28708");

  script_name(english:"Nutanix AOS : (NXSA-AOS-6.5.3.5)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.5.3.5. It is, therefore, affected by a vulnerability as
referenced in the NXSA-AOS-6.5.3.5 advisory.

  - When using the RemoteIpFilter with requests received from a reverse proxy via HTTP that include the
    X-Forwarded-Proto header set to https, session cookies created by Apache Tomcat 11.0.0-M1 to 11.0.0.-M2,
    10.1.0-M1 to 10.1.5, 9.0.0-M1 to 9.0.71 and 8.5.0 to 8.5.85 did not include the secure attribute. This
    could result in the user agent transmitting the session cookie over an insecure channel. (CVE-2023-28708)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.5.3.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a182d67");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '6.5.3.5', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.5.3.5 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '6.5.3.5', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.5.3.5 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);

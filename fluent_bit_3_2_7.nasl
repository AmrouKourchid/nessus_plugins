#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216915);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2024-50608", "CVE-2024-50609");
  script_cwe_id(476);
  script_xref(name:"IAVA", value:"2025-A-0132");

  script_name(english:"Fluent Bit Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A logging processor application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Fluent Bit running on the remote host is prior
to 3.2.7. It is, therefore, is affected by multiple vulnerabilities:

  - An issue was discovered in Fluent Bit 3.1.9. When the Prometheus Remote Write input plugin is running 
    and listening on an IP address and port, one can send a packet with Content-Length: 0 and it crashes 
    the server. Improper handling of the case when Content-Length is 0 allows a user (with access to the 
    endpoint) to perform a remote Denial of service attack. The crash happens because of a NULL pointer 
    dereference when 0 (from the Content-Length) is passed to the function cfl_sds_len, which in turn tries 
    to cast a NULL pointer into struct cfl_sds. This is related to process_payload_metrics_ng() at 
    prom_rw_prot.c. (CVE-2024-50608)
    
  - An issue was discovered in Fluent Bit 3.1.9. When the OpenTelemetry input plugin is running 
    and listening on an IP address and port, one can send a packet with Content-Length: 0 and it 
    crashes the server. Improper handling of the case when Content-Length is 0 allows a user (with 
    access to the endpoint) to perform a remote Denial of service attack. The crash happens because 
    of a NULL pointer dereference when 0 (from the Content-Length) is passed to the function cfl_sds_len, 
    which in turn tries to cast a NULL pointer into struct cfl_sds. This is related to 
    process_payload_traces_proto_ng() at opentelemetry_prot.c. (CVE-2024-50609)

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://fluentbit.io/announcements/v3.2.7/");
  # https://www.ebryx.com/blogs/exploring-cve-2024-50608-and-cve-2024-50609
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7be4e4d2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to v3.2.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50608");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:fluent_bit:fluent_bit");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fluent_bit_detect.nbin");
  script_require_keys("installed_sw/Fluent Bit");

  exit(0);
}

include('vcf.inc');
include('webapp_func.inc');

var app = 'Fluent Bit';
var port = get_http_port(default:2020);
var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  {'min_version':'3.1.0', 'fixed_version':'3.2.7'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

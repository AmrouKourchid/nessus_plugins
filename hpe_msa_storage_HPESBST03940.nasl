#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(179601);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/10");

  script_cve_id("CVE-2019-12001", "CVE-2019-12002");

  script_name(english:"HPE MSA Storage Session Reuse (HPESBST03940)");

  script_set_attribute(attribute:"synopsis", value:
"The remote storage device is affected by a session reuse vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HPE MSA Storage installed on the remote host is prior to GL225P002-02, VE270P002-02, or VL270P002-02. It is, therefore,
affected by a vulnerability as referenced in the HPESBST03940 advisory.

  - A remote session reuse vulnerability leading to access restriction bypass 
    was discovered in HPE MSA 2040 SAN Storage; HPE MSA 1040 SAN Storage;
    HPE MSA 1050 SAN Storage; HPE MSA 2042 SAN Storage;
    HPE MSA 2050 SAN Storage; HPE MSA 2052 SAN Storage version(s): GL225P001
    and earlier; GL225P001 and earlier; VE270R001-01 and earlier; GL225P001 and
    earlier; VL270R001-01 and earlier; VL270R001-01 and earlier.
    (CVE-2019-12002, CVE-2019-12001)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-hpesbst03940en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65ff3d83");
  script_set_attribute(attribute:"solution", value:
"Update to HPE MSA 1040 firmware version GL225P002-02, HPE MSA 2040 firmware
version GL225P002-02, HPE MSA 2042 firmware version GL225P002-02, HPE MSA 1050
firmware version VE270P002-02, HPE MSA 2050 firmware version VL270P002-02, HPE
MSA 2052 firmware version VL270P002-02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12002");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hpe:msa_1040_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hpe:msa_1040");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hpe:msa_1050_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hpe:msa_1050");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hpe:msa_2040_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hpe:msa_2040");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hpe:msa_2042_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hpe:msa_2042");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hpe:msa_2050_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hpe:msa_2050");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hpe:msa_2052_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hpe:msa_2052");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:hpe:msa");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:hpe:msa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_powervault_slp_detect.nbin");
  script_require_keys("installed_sw/HPE MSA Storage");

  exit(0);
}

include('vcf.inc');

var port = get_one_kb_item("Services/udp/slp");
if (empty_or_null(object: port ))
  port = 427;

var app_info = vcf::get_app_info(app:'HPE MSA Storage', port:port);

var constraints;
if (app_info.Model =~ 'MSA 1040' ||
    app_info.Model =~ 'MSA 2040' ||
    app_info.Model =~ 'MSA 2042' )
  constraints = [{'fixed_version' : '225.002.02', 'fixed_display' : 'GL225P002-02' }];
else if (app_info.Model =~ 'MSA 1050')
  constraints = [{'fixed_version' : '270.002.02', 'fixed_display' : 'VE270P002-02' }];
else if (app_info.Model =~ 'MSA 2050' ||
         app_info.Model =~ 'MSA 2052' )
  constraints = [{'fixed_version' : '270.002.02', 'fixed_display' : 'VL270P002-02' }];
else
  audit(AUDIT_HOST_NOT, 'an affected model');

var matches = pregmatch(string:app_info.version, pattern:"^[A-Z]{2}(\d{3})[A-Z](\d{3})-?(\d\d)?$");
if (empty_or_null(object:matches) || empty_or_null(object: (matches[0]))  || empty_or_null(object: (matches[1])) || empty_or_null(object: (matches[2])) || empty_or_null(object: (matches[3])))
  audit(AUDIT_VER_NOT_GRANULAR, '');

  app_info.parsed_version = vcf::parse_version(matches[1]+'.'+matches[2]+'.'+matches[3]);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

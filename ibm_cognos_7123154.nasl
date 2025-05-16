#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193868);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/18");

  script_cve_id(
    "CVE-2012-5784",
    "CVE-2014-3596",
    "CVE-2018-8032",
    "CVE-2019-0227",
    "CVE-2019-1547",
    "CVE-2020-1971",
    "CVE-2020-28458",
    "CVE-2021-3449",
    "CVE-2021-3572",
    "CVE-2021-3711",
    "CVE-2021-3712",
    "CVE-2021-4160",
    "CVE-2021-23445",
    "CVE-2021-23839",
    "CVE-2021-23840",
    "CVE-2021-23841",
    "CVE-2021-28167",
    "CVE-2021-31684",
    "CVE-2021-35550",
    "CVE-2021-35556",
    "CVE-2021-35559",
    "CVE-2021-35560",
    "CVE-2021-35564",
    "CVE-2021-35565",
    "CVE-2021-35578",
    "CVE-2021-35586",
    "CVE-2021-35588",
    "CVE-2021-35603",
    "CVE-2021-41035",
    "CVE-2021-43138",
    "CVE-2021-44906",
    "CVE-2022-0778",
    "CVE-2022-1471",
    "CVE-2022-2097",
    "CVE-2022-21299",
    "CVE-2022-21434",
    "CVE-2022-21443",
    "CVE-2022-21496",
    "CVE-2022-34169",
    "CVE-2022-34357",
    "CVE-2022-40897",
    "CVE-2022-41854",
    "CVE-2023-0215",
    "CVE-2023-0464",
    "CVE-2023-1370",
    "CVE-2023-2597",
    "CVE-2023-3817",
    "CVE-2023-21930",
    "CVE-2023-21937",
    "CVE-2023-21938",
    "CVE-2023-21939",
    "CVE-2023-21954",
    "CVE-2023-21967",
    "CVE-2023-21968",
    "CVE-2023-22049",
    "CVE-2023-26115",
    "CVE-2023-26136",
    "CVE-2023-30588",
    "CVE-2023-30589",
    "CVE-2023-30996",
    "CVE-2023-32344",
    "CVE-2023-36478",
    "CVE-2023-38359",
    "CVE-2023-39410",
    "CVE-2023-43051",
    "CVE-2023-44487",
    "CVE-2023-45857"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVB", value:"2024-B-0046-S");

  script_name(english:"IBM Cognos Analytics 11.1.1 < 11.1.7 FP8 / 11.2.x < 11.2.4 FP3 / 12.0.x < 12.0.2 (7123154)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Cognos Analytics installed on the remote host is prior to 11.1.7 FP8, 11.2.4 FP3, or 12.0.2. It is,
therefore, affected by multiple vulnerabilities as referenced in the IBM Security Bulletin No. 7123154, including the
following:

  - When deserializing untrusted or corrupted data, it is possible for a reader to consume memory beyond the 
  allowed constraints and thus lead to out of memory on the system. This issue affects Java applications using
  Apache Avro Java SDK up to and including 1.11.2. Users should update to apache-avro version 1.11.3 which
  addresses this issue. (CVE-2023-39410)

  - In order to decrypt SM2 encrypted data an application is expected to call the API function
  EVP_PKEY_decrypt(). Typically an application will call this function twice. The first time, on entry, the
  'out' parameter can be NULL and, on exit, the 'outlen' parameter is populated with the buffer size required
  to hold the decrypted plaintext. The application can then allocate a sufficiently sized buffer and call
  EVP_PKEY_decrypt() again, but this time passing a non-NULL value for the 'out' parameter. A bug in the
  implementation of the SM2 decryption code means that the calculation of the buffer size required to hold the
  plaintext returned by the first call to EVP_PKEY_decrypt() can be smaller than the actual size required by
  the second call. This can lead to a buffer overflow when EVP_PKEY_decrypt() is called by the application a
  second time with a buffer that is too small. A malicious attacker who is able present SM2 content for
  decryption to an application could cause attacker chosen data to overflow the buffer by up to a maximum of
  62 bytes altering the contents of other data held after the buffer, possibly changing application behaviour
  or causing the application to crash. The location of the buffer is application dependent but is typically
  heap allocated. Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). (CVE-2021-3711)

  - SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization.
  Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using 
  SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend 
  upgrading to version 2.0 and beyond. (CVE-2022-1471)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7123154");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Cognos Analytics version 11.1.7 FP8 / 11.2.4 FP3 / 12.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44906");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-26136");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:cognos_analytics");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_cognos_analytics_web_detect.nbin");
  script_require_keys("installed_sw/IBM Cognos Analytics");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'IBM Cognos Analytics';

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '11.1.1', 'max_version' : '11.1.7.999999', 'fixed_display' : '11.1.7 FP8', 'require_paranoia' : TRUE },
  { 'min_version' : '11.2.0', 'max_version' : '11.2.4.999999', 'fixed_display' : '11.2.4 FP3', 'require_paranoia' : TRUE },
  { 'min_version' : '12.0.0', 'fixed_version' : '12.0.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
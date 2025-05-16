#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(194919);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id(
    "CVE-2017-16042",
    "CVE-2018-25032",
    "CVE-2019-10744",
    "CVE-2019-10746",
    "CVE-2019-20149",
    "CVE-2020-7662",
    "CVE-2020-7753",
    "CVE-2020-7774",
    "CVE-2020-8116",
    "CVE-2020-8169",
    "CVE-2020-8177",
    "CVE-2020-8203",
    "CVE-2020-8231",
    "CVE-2020-8284",
    "CVE-2020-8285",
    "CVE-2020-8286",
    "CVE-2020-13822",
    "CVE-2020-15138",
    "CVE-2020-28469",
    "CVE-2021-3520",
    "CVE-2021-3803",
    "CVE-2021-20095",
    "CVE-2021-22876",
    "CVE-2021-22890",
    "CVE-2021-22897",
    "CVE-2021-22898",
    "CVE-2021-22901",
    "CVE-2021-22922",
    "CVE-2021-22923",
    "CVE-2021-22924",
    "CVE-2021-22925",
    "CVE-2021-22926",
    "CVE-2021-22945",
    "CVE-2021-22946",
    "CVE-2021-22947",
    "CVE-2021-23343",
    "CVE-2021-23368",
    "CVE-2021-23382",
    "CVE-2021-27292",
    "CVE-2021-29060",
    "CVE-2021-31566",
    "CVE-2021-33502",
    "CVE-2021-33503",
    "CVE-2021-33587",
    "CVE-2021-36976",
    "CVE-2021-43565",
    "CVE-2022-1705",
    "CVE-2022-1962",
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-3517",
    "CVE-2022-4200",
    "CVE-2022-4304",
    "CVE-2022-22576",
    "CVE-2022-23491",
    "CVE-2022-23772",
    "CVE-2022-23773",
    "CVE-2022-23806",
    "CVE-2022-24675",
    "CVE-2022-24921",
    "CVE-2022-24999",
    "CVE-2022-25858",
    "CVE-2022-27191",
    "CVE-2022-27664",
    "CVE-2022-27774",
    "CVE-2022-27775",
    "CVE-2022-27776",
    "CVE-2022-27778",
    "CVE-2022-27779",
    "CVE-2022-27780",
    "CVE-2022-27781",
    "CVE-2022-27782",
    "CVE-2022-28131",
    "CVE-2022-28327",
    "CVE-2022-29526",
    "CVE-2022-29804",
    "CVE-2022-30115",
    "CVE-2022-30580",
    "CVE-2022-30629",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30634",
    "CVE-2022-30635",
    "CVE-2022-31129",
    "CVE-2022-32148",
    "CVE-2022-32189",
    "CVE-2022-32205",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208",
    "CVE-2022-32221",
    "CVE-2022-33987",
    "CVE-2022-35252",
    "CVE-2022-35260",
    "CVE-2022-35737",
    "CVE-2022-36227",
    "CVE-2022-37434",
    "CVE-2022-37599",
    "CVE-2022-37601",
    "CVE-2022-37603",
    "CVE-2022-37616",
    "CVE-2022-38900",
    "CVE-2022-40023",
    "CVE-2022-40303",
    "CVE-2022-40304",
    "CVE-2022-41715",
    "CVE-2022-41716",
    "CVE-2022-41720",
    "CVE-2022-42004",
    "CVE-2022-42915",
    "CVE-2022-42916",
    "CVE-2022-43551",
    "CVE-2022-43552",
    "CVE-2022-43680",
    "CVE-2022-46175",
    "CVE-2023-0215",
    "CVE-2023-0286",
    "CVE-2023-1370",
    "CVE-2023-23914",
    "CVE-2023-23915",
    "CVE-2023-23916",
    "CVE-2023-27533",
    "CVE-2023-27534",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27537",
    "CVE-2023-27538"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Splunk Enterprise < 8.1.14, 8.2.0 < 8.2.11, 9.0.0 < 9.0.5 (SVD-2023-0613)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Splunk installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the SVD-2023-0613 advisory.

  - A prototype pollution vulnerability exists in the function copy in dom.js in the xmldom (published as
    @xmldom/xmldom) package before 0.8.3 for Node.js via the p variable. NOTE: the vendor states we are in
    the process of marking this report as invalid; however, some third parties takes the position that A
    prototype injection/Prototype pollution is not just when global objects are polluted with recursive merge
    or deep cloning but also when a target object is polluted. (CVE-2022-37616)

  - When curl < 7.84.0 saves cookies, alt-svc and hsts data to local files, it makes the operation atomic by
    finalizing the operation with a rename from a temporary name to the final target file name.In that rename
    operation, it might accidentally *widen* the permissions for the target file, leaving the updated file
    accessible to more users than intended. (CVE-2022-32207)

  - An issue was discovered in libxml2 before 2.10.3. When parsing a multi-gigabyte XML document with the
    XML_PARSE_HUGE parser option enabled, several integer counters can overflow. This results in an attempt to
    access an array at a negative 2GB offset, typically leading to a segmentation fault. (CVE-2022-40303)

  - An issue was discovered in libxml2 before 2.10.3. Certain invalid XML entity definitions can corrupt a
    hash table key, potentially leading to subsequent logic errors. In one case, a double-free can be
    provoked. (CVE-2022-40304)

  - There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName.
    X.400 addresses were parsed as an ASN1_STRING but the public structure definition for GENERAL_NAME
    incorrectly specified the type of the x400Address field as ASN1_TYPE. This field is subsequently
    interpreted by the OpenSSL function GENERAL_NAME_cmp as an ASN1_TYPE rather than an ASN1_STRING. When CRL
    checking is enabled (i.e. the application sets the X509_V_FLAG_CRL_CHECK flag), this vulnerability may
    allow an attacker to pass arbitrary pointers to a memcmp call, enabling them to read memory contents or
    enact a denial of service. In most cases, the attack requires the attacker to provide both the certificate
    chain and CRL, neither of which need to have a valid signature. If the attacker only controls one of these
    inputs, the other input must already contain an X.400 address as a CRL distribution point, which is
    uncommon. As such, this vulnerability is most likely to only affect applications which have implemented
    their own functionality for retrieving CRLs over a network. (CVE-2023-0286)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://advisory.splunk.com/advisories/SVD-2023-0613.html");
  script_set_attribute(attribute:"solution", value:
"For Splunk Enterprise, upgrade versions to 8.1.14, 8.2.11, 9.0.5, or higher.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32207");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37616");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl", "macos_splunk_installed.nbin", "splunk_win_installed.nbin", "splunk_nix_installed.nbin");
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_splunk.inc');

var app_info = vcf::splunk::get_app_info();

var constraints = [
  { 'fixed_version' : '8.1.14', 'license' : 'Enterprise' },
  { 'min_version' : '8.2.0', 'fixed_version' : '8.2.11', 'license' : 'Enterprise' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.5', 'license' : 'Enterprise' }
];
vcf::splunk::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);

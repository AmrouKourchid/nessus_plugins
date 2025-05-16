#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186765);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id(
    "CVE-2023-47064",
    "CVE-2023-47065",
    "CVE-2023-48440",
    "CVE-2023-48441",
    "CVE-2023-48442",
    "CVE-2023-48443",
    "CVE-2023-48444",
    "CVE-2023-48445",
    "CVE-2023-48446",
    "CVE-2023-48447",
    "CVE-2023-48448",
    "CVE-2023-48449",
    "CVE-2023-48450",
    "CVE-2023-48451",
    "CVE-2023-48452",
    "CVE-2023-48453",
    "CVE-2023-48454",
    "CVE-2023-48455",
    "CVE-2023-48456",
    "CVE-2023-48457",
    "CVE-2023-48458",
    "CVE-2023-48459",
    "CVE-2023-48460",
    "CVE-2023-48461",
    "CVE-2023-48462",
    "CVE-2023-48463",
    "CVE-2023-48464",
    "CVE-2023-48465",
    "CVE-2023-48466",
    "CVE-2023-48467",
    "CVE-2023-48468",
    "CVE-2023-48469",
    "CVE-2023-48470",
    "CVE-2023-48471",
    "CVE-2023-48472",
    "CVE-2023-48473",
    "CVE-2023-48474",
    "CVE-2023-48475",
    "CVE-2023-48476",
    "CVE-2023-48477",
    "CVE-2023-48478",
    "CVE-2023-48479",
    "CVE-2023-48480",
    "CVE-2023-48481",
    "CVE-2023-48482",
    "CVE-2023-48483",
    "CVE-2023-48484",
    "CVE-2023-48485",
    "CVE-2023-48486",
    "CVE-2023-48487",
    "CVE-2023-48488",
    "CVE-2023-48489",
    "CVE-2023-48490",
    "CVE-2023-48491",
    "CVE-2023-48492",
    "CVE-2023-48493",
    "CVE-2023-48494",
    "CVE-2023-48495",
    "CVE-2023-48496",
    "CVE-2023-48497",
    "CVE-2023-48498",
    "CVE-2023-48499",
    "CVE-2023-48500",
    "CVE-2023-48501",
    "CVE-2023-48502",
    "CVE-2023-48503",
    "CVE-2023-48504",
    "CVE-2023-48505",
    "CVE-2023-48506",
    "CVE-2023-48507",
    "CVE-2023-48508",
    "CVE-2023-48509",
    "CVE-2023-48510",
    "CVE-2023-48511",
    "CVE-2023-48512",
    "CVE-2023-48513",
    "CVE-2023-48514",
    "CVE-2023-48515",
    "CVE-2023-48516",
    "CVE-2023-48517",
    "CVE-2023-48518",
    "CVE-2023-48519",
    "CVE-2023-48520",
    "CVE-2023-48521",
    "CVE-2023-48522",
    "CVE-2023-48523",
    "CVE-2023-48524",
    "CVE-2023-48525",
    "CVE-2023-48526",
    "CVE-2023-48527",
    "CVE-2023-48528",
    "CVE-2023-48529",
    "CVE-2023-48530",
    "CVE-2023-48531",
    "CVE-2023-48532",
    "CVE-2023-48533",
    "CVE-2023-48534",
    "CVE-2023-48535",
    "CVE-2023-48536",
    "CVE-2023-48537",
    "CVE-2023-48538",
    "CVE-2023-48539",
    "CVE-2023-48540",
    "CVE-2023-48541",
    "CVE-2023-48542",
    "CVE-2023-48543",
    "CVE-2023-48544",
    "CVE-2023-48545",
    "CVE-2023-48546",
    "CVE-2023-48547",
    "CVE-2023-48548",
    "CVE-2023-48549",
    "CVE-2023-48550",
    "CVE-2023-48551",
    "CVE-2023-48552",
    "CVE-2023-48553",
    "CVE-2023-48554",
    "CVE-2023-48555",
    "CVE-2023-48556",
    "CVE-2023-48557",
    "CVE-2023-48558",
    "CVE-2023-48559",
    "CVE-2023-48560",
    "CVE-2023-48561",
    "CVE-2023-48562",
    "CVE-2023-48563",
    "CVE-2023-48564",
    "CVE-2023-48565",
    "CVE-2023-48566",
    "CVE-2023-48567",
    "CVE-2023-48568",
    "CVE-2023-48569",
    "CVE-2023-48570",
    "CVE-2023-48571",
    "CVE-2023-48572",
    "CVE-2023-48573",
    "CVE-2023-48574",
    "CVE-2023-48575",
    "CVE-2023-48576",
    "CVE-2023-48577",
    "CVE-2023-48578",
    "CVE-2023-48579",
    "CVE-2023-48580",
    "CVE-2023-48581",
    "CVE-2023-48582",
    "CVE-2023-48583",
    "CVE-2023-48584",
    "CVE-2023-48585",
    "CVE-2023-48586",
    "CVE-2023-48587",
    "CVE-2023-48588",
    "CVE-2023-48589",
    "CVE-2023-48590",
    "CVE-2023-48591",
    "CVE-2023-48592",
    "CVE-2023-48593",
    "CVE-2023-48594",
    "CVE-2023-48595",
    "CVE-2023-48596",
    "CVE-2023-48597",
    "CVE-2023-48598",
    "CVE-2023-48599",
    "CVE-2023-48600",
    "CVE-2023-48601",
    "CVE-2023-48602",
    "CVE-2023-48603",
    "CVE-2023-48604",
    "CVE-2023-48605",
    "CVE-2023-48606",
    "CVE-2023-48607",
    "CVE-2023-48608",
    "CVE-2023-48609",
    "CVE-2023-48610",
    "CVE-2023-48611",
    "CVE-2023-48612",
    "CVE-2023-48613",
    "CVE-2023-48614",
    "CVE-2023-48615",
    "CVE-2023-48616",
    "CVE-2023-48617",
    "CVE-2023-48618",
    "CVE-2023-48619",
    "CVE-2023-48620",
    "CVE-2023-48621",
    "CVE-2023-48622",
    "CVE-2023-48623",
    "CVE-2023-48624",
    "CVE-2023-51457",
    "CVE-2023-51458",
    "CVE-2023-51459",
    "CVE-2023-51460",
    "CVE-2023-51461",
    "CVE-2023-51462",
    "CVE-2023-51463",
    "CVE-2023-51464"
  );
  script_xref(name:"IAVA", value:"2023-A-0685-S");

  script_name(english:"Adobe Experience Manager 6.5.0.0 < 6.5.19.0 Multiple Vulnerabilities (APSB23-72)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to 6.5.19.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB23-72 advisory.

  - Adobe Experience Manager versions 6.5.18 and earlier are affected by a stored Cross-Site Scripting (XSS)
    vulnerability that could be abused by a low-privileged attacker to inject malicious scripts into
    vulnerable form fields. Malicious JavaScript may be executed in a victim's browser when they browse to the
    page containing the vulnerable field. (CVE-2023-47064, CVE-2023-48440, CVE-2023-48442, CVE-2023-48444,
    CVE-2023-48481, CVE-2023-48501, CVE-2023-48503, CVE-2023-48504, CVE-2023-48505, CVE-2023-48506,
    CVE-2023-48507, CVE-2023-48508, CVE-2023-48511, CVE-2023-48512, CVE-2023-48513, CVE-2023-48514,
    CVE-2023-48515, CVE-2023-48516, CVE-2023-48517, CVE-2023-48518, CVE-2023-48519, CVE-2023-48520,
    CVE-2023-48521, CVE-2023-48522, CVE-2023-48523, CVE-2023-48524, CVE-2023-48527, CVE-2023-48529,
    CVE-2023-48530, CVE-2023-48531, CVE-2023-48533, CVE-2023-48534, CVE-2023-48537, CVE-2023-48538,
    CVE-2023-48540, CVE-2023-48542, CVE-2023-48543, CVE-2023-48544, CVE-2023-48545, CVE-2023-48546,
    CVE-2023-48547, CVE-2023-48548, CVE-2023-48549, CVE-2023-48550, CVE-2023-48551, CVE-2023-48552,
    CVE-2023-48553, CVE-2023-48554, CVE-2023-48555, CVE-2023-48557, CVE-2023-48558, CVE-2023-48559,
    CVE-2023-48560, CVE-2023-48561, CVE-2023-48562, CVE-2023-48563, CVE-2023-48564, CVE-2023-48569,
    CVE-2023-48570, CVE-2023-48571, CVE-2023-48572, CVE-2023-48573, CVE-2023-48574, CVE-2023-48575,
    CVE-2023-48576, CVE-2023-48577, CVE-2023-48578, CVE-2023-48579, CVE-2023-48580, CVE-2023-48581,
    CVE-2023-48582, CVE-2023-48584, CVE-2023-48585, CVE-2023-48586, CVE-2023-48588, CVE-2023-48592,
    CVE-2023-48593, CVE-2023-48594, CVE-2023-48595, CVE-2023-48596, CVE-2023-48597, CVE-2023-48598,
    CVE-2023-48600, CVE-2023-48602, CVE-2023-48603, CVE-2023-48604, CVE-2023-48613, CVE-2023-48615,
    CVE-2023-48616, CVE-2023-48619, CVE-2023-48620, CVE-2023-48622, CVE-2023-48624, CVE-2023-51457,
    CVE-2023-51458, CVE-2023-51460, CVE-2023-51461, CVE-2023-51464)

  - Adobe Experience Manager versions 6.5.18 and earlier are affected by an Improper Access Control
    vulnerability. An attacker could leverage this vulnerability to achieve a low-confidentiality impact
    within the application. Exploitation of this issue does not require user interaction. (CVE-2023-48441)

  - Adobe Experience Manager versions 6.5.18 and earlier are affected by a reflected Cross-Site Scripting
    (XSS) vulnerability. If a low-privileged attacker is able to convince a victim to visit a URL referencing
    a vulnerable page, malicious JavaScript content may be executed within the context of the victim's
    browser. (CVE-2023-48443, CVE-2023-48447, CVE-2023-48448, CVE-2023-48455, CVE-2023-48497, CVE-2023-48498,
    CVE-2023-48499, CVE-2023-48500, CVE-2023-48526, CVE-2023-48601, CVE-2023-48607, CVE-2023-48621,
    CVE-2023-48623, CVE-2023-51459, CVE-2023-51462, CVE-2023-51463)

  - Adobe Experience Manager versions 6.5.18 and earlier are affected by a Cross-site Scripting (DOM-based
    XSS) vulnerability. If a low-privileged attacker is able to convince a victim to visit a URL referencing a
    vulnerable page, malicious JavaScript content may be executed within the context of the victim's browser.
    (CVE-2023-47065, CVE-2023-48445, CVE-2023-48446, CVE-2023-48449, CVE-2023-48450, CVE-2023-48451,
    CVE-2023-48452, CVE-2023-48453, CVE-2023-48454, CVE-2023-48456, CVE-2023-48457, CVE-2023-48458,
    CVE-2023-48459, CVE-2023-48460, CVE-2023-48461, CVE-2023-48462, CVE-2023-48463, CVE-2023-48464,
    CVE-2023-48465, CVE-2023-48466, CVE-2023-48467, CVE-2023-48468, CVE-2023-48469, CVE-2023-48470,
    CVE-2023-48471, CVE-2023-48472, CVE-2023-48473, CVE-2023-48474, CVE-2023-48475, CVE-2023-48476,
    CVE-2023-48477, CVE-2023-48478, CVE-2023-48479, CVE-2023-48480, CVE-2023-48482, CVE-2023-48483,
    CVE-2023-48484, CVE-2023-48485, CVE-2023-48486, CVE-2023-48487, CVE-2023-48488, CVE-2023-48489,
    CVE-2023-48490, CVE-2023-48491, CVE-2023-48492, CVE-2023-48493, CVE-2023-48494, CVE-2023-48495,
    CVE-2023-48496, CVE-2023-48502, CVE-2023-48509, CVE-2023-48510, CVE-2023-48525, CVE-2023-48528,
    CVE-2023-48532, CVE-2023-48535, CVE-2023-48536, CVE-2023-48539, CVE-2023-48541, CVE-2023-48556,
    CVE-2023-48565, CVE-2023-48566, CVE-2023-48567, CVE-2023-48568, CVE-2023-48583, CVE-2023-48587,
    CVE-2023-48589, CVE-2023-48590, CVE-2023-48591, CVE-2023-48599, CVE-2023-48605, CVE-2023-48606,
    CVE-2023-48609, CVE-2023-48610, CVE-2023-48611, CVE-2023-48612, CVE-2023-48614, CVE-2023-48617,
    CVE-2023-48618)

  - Adobe Experience Manager versions 6.5.18 and earlier are affected by an Improper Input Validation
    vulnerability. A low-privileged attacker could leverage this vulnerability to achieve a low-integrity
    impact within the application. Exploitation of this issue requires user interaction. (CVE-2023-48608)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb23-72.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e7b80e0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5.19.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-51464");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_experience_manager_http_detect.nbin");
  script_require_keys("installed_sw/Adobe Experience Manager");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:4502);
var app_info = vcf::get_app_info(app:'Adobe Experience Manager', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '6.5.0.0', 'fixed_version' : '6.5.19.0' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);

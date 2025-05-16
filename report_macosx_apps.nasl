#TRUSTED 0f0458661de8eddeb0e8fbe6ccd6df31c1c7a9219f1deca9542a47dc0e5d6b479402ebf51699c820e3d2d00e708da46bad4732035183ba93f92e28f67afecdea4d8439791cff0e09d73f9a457f660b0b3d83d4925ebe1d07ba8fc49da0f5a41ff1de0a4f774238c7ba6cda0c82445bc53da6576c5235a6eef20f07e12efec0a536433ce108732ec6d377d387f170551c8afbf1e681085acd7a3178797a78205a0a2c9036f4b0d6dcfb1dd773d17a4b01048f27e5386b4054058422032d555ed24cec420a25ff0eab1aa317e889a55a6e51e1c997164d508c521bac020bb734523ea7bc2c5cf46bface5fb3c219c512859189e3659f3063081f6ebf4b8a84f27836af73eb014e2f4f753aeeba773b5a6f287e325922cb1d966cf88a9c278fa51b0fac101d08d55837545982d23b2897d781433a862c6fc7dad849f478f02538127152da08142aff478234e4fcafee915215b11ac590e335f503d97f533b138bc28f37a0626fee1aebd779634e02f82698ea13814da48301049a129874bacb0da4f7894e2fa31e71e33fb1220924246f152d4745c0d54c2ebaae2af309a7e70b42f65fb4b7b4d8e617f1d7490d036263898ed36e4de7b926412ff4459adf507124c802660072d50d8b9db43c25f075a8588959e0a96b8be3f674c026f48ef65a5d6ffe38bb7a8337a7e1fb89f777278e2a8114f0afa78679c220687f4f52381dfd
#TRUST-RSA-SHA256 8d7e94353b12dc055803ffc17c4f9e8f2d2060b19dd2eb63395f7887a37d0f44caa23bbe9b219b7f251396b9b2b8f1d48b5804df694c87ce17c69aa12e1bbd9e77f8b3418944201533b74042f7724f8fff3e7545246daa71bd40bee1324c163ea03ee44cbc69c8b06178a90d9bb83653b31cd0188cda63a95cc9b5821b4b4f1fdd2dec482f4efbdd602a408fc82ece7891a87b62bc85852ac2da03a451d2b0ca498f7fe453eb37c690997a4e391aa3a5f404b929d4571eb3251c6db8091f96d986635efc75784108d85f6ff07d2232e4bd08c130671204e5330c59637dea15d80aa87bcb81e892ba92a4b30245d15d48cedca354df486f5d98c91c18db286a9aaf3c4a87d50cdf559db8ce5a29e7dff1f30efa6a12b0f6487f2851e6844911f077f1653ea004d5d2b0916bb8a0bd7fdbc003df8732f63c0e26d37cfda3c09d633c5cc1214458634f1f79b2d4c2eb28515004e9d264e827acfdb6df41f89885c5888c51e6303348e5def42415cc403994d432d508bfe8c270390c98694a96d31ab46d0dd21e04c24a61e8f2c6c0fa1b325104ce544abe795092ce57c94c7779d3e0396fb42c270c97e6f7cbde3f788f9a715bfe02e92a2bf92066beb24ece7681483c9382b27bc9b158efde66222c0b18b80da62df5e507770071edcc4bc93c3e15b8d0867764b599b98879f248d5a881f833418e25531f9bc94fe40e6859a00d
#%NASL_MIN_LEVEL 80900

##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232590);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/11");

  script_name(english:"MacOS X Applications Enumerated Software Report");

  script_set_attribute(attribute:"synopsis", value:"Reports details about software enumerated from installed MacOS X applications");
  script_set_attribute(attribute:"description", value:"Reports details about software enumerated from installed MacOS X applications");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/11");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_END2);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_eval_installed.nbin");
  script_require_keys("MacOSX/packages/sys_profiler");

  exit(0);
}

include('macosx_software_eval_funcs.inc');
include('json2.inc');
include('structured_data.inc');

exit(0, "This plugin is currently disabled");

var installed_software = new structured_data_installed_sw();

var software = osx_get_enumerated_software();

foreach var install (software)
{
  if(isnull(install['application']) || isnull(install['location'])) continue;

  # Skip install if already registered by a detection plugin.
  var existing_installs = get_installs(app_name:install['application']);
  if(existing_installs[0] == IF_OK)
  {
    var skip = false;
    existing_installs = existing_installs[1];
    if(!isnull(existing_installs) && len(existing_installs > 0))
    {
      foreach var existing_install (existing_installs)
      {
        if(existing_install['path'] == install['location'])
        {
          skip = true;
          break;
        }
      }
      
      if (skip) continue;
    }
  }
  
  var data = {
    'string_id': hexstr(SHA256(install['location'])),
    'app_name': 'MacOSApps:' + install['application'],
    'product': install['application'],
    'path': install['location'],
    'vendor': 'Unknown'
  };

  if(!empty_or_null(install['signed_by']))
  {
    if(install['signed_by'] == 'Software Signing, Apple Code Signing Certification Authority, Apple Root CA')
    {
      data['vendor'] = 'Apple';
    }
    else
    {
      var match = pregmatch(pattern:'^Developer ID Application:\\s+(.+?)\\s+\\(.+$', string:install['signed_by'], icase:true);
      if(!empty_or_null(match) && !empty_or_null(match[1]))
      {
        data['vendor'] = match[1];
      }
    }
  }

  if(!empty_or_null(install['version']))
  {
    data['version'] = install['version'];
  }

  installed_software.append('installs', data);
}

installed_software.report_internal();
security_report_v4(port:0, extra:'Successfully retrieved and stored MacOS X applications enumerated software.', severity:SECURITY_NOTE);
#TRUSTED 59c14c0f604a0ef67803a71d0c3ad2af54937ce9b83003b219eca4c1d36eaac78991815ef912246b40a8593b12e17760756bf45c736351ae8685181932742c871b2bd648db353520173153957b04546585ac044eb9f40c4aa4450caa44e015c6ebd7ab75677126eebc110dc9c807c53a61c4580e7cd54fa204a16509a4fd9686f782c51575018a55039bc05d83a015cbacd069b2918dd0736035ded4ffc8efc117f72a68290265c9f26d8a6fd8a4af5219e8b8b1b521a639f73ba8d89c7bc1840ef2f82a83d172648d3e6b064638343c127d01331c6c86bc436eecfe05c27c0716d4ba36d5f23606b4ff3cc45acf5348eb26246c5b194287587ecb776f648d41f388e2be658093d6397330bfb597f59fd97d9aa3697b469e7193948b53d9c498191c7633588220b3b4c155818aa1249431f2317e36d0fb584eab7a4110d48f24c9e8fcda0a4fe73455dfaaef298fb03f5b0403a1899fa48fd1ba29316e4079d789ec9d5a8c3282081452c84bde059783f3a64e5bb20772bd9cf81508491f7f01554893738b48b055567400d012b2dd9d3e686df51cf26e941ecc2f732d9b22175fa2842431234f2dd0046db4ffa3b6ccc8732bfdd1e88910065c9f6c57276512c47aea2b11c9d7641bfdddd0bde458182cb20ebe4944ab9412b34cdb4c2ab2dd793375712c08faed1323f17e10edc773f3484a73c48050c7aae6cc4e4fb8b3fe

#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
include('compat_shared.inc');
include('json2.inc');
include('path.inc');

object prelim_data
{
  var data = {
      "plugin_id": 0,
      "revision": 0,
      "start_time": 0,
      "end_time": 0,
      "logs": [],
      "items":  []
    };
  var tag_name;
  var mark_count = 0;
  
  ##
  # Constructor
  ##
  function prelim_data()
  {
    set_plugin_id(_FCT_ANON_ARGS[0]);
    set_revision(_FCT_ANON_ARGS[1]);
    make_tag_name();
  }
  
  ##
  # Timestamps the start of the data collection.
  ##
  public function begin()
  {
    this.data.start_time = gettimeofday();
  }
  
  ##
  # Stores a timestamp mark in the data array. Used for fine
  # tuning performance metrics during data analysis.
  ##
  public function mark()
  {
    append_element(
      var: this.data.items,
      value: {
        name:'mark-' + mark_count, 
        timestamp: gettimeofday()
      }
    );
    this.mark_count++;
  }
  
  ##
  # Report host tags for plugin audit out.
  ##
  public function abort()
  {
    this.data.status = 'aborted';
    report();
  }
  
  ##
  # Ends data collection and reports findings in host tag.
  ##
  public function done()
  {
    this.data.status = 'success';
    report();
  }
  
  ##
  # Sets the plugin id.
  #
  # @param id Plugin id.
  ##
  public function set_plugin_id(id)
  {
    if(!id) this.data.plugin_id = _FCT_ANON_ARGS[0];
    else this.data.plugin_id = 0;
  }
  
  ##
  # Sets  the data collection revision.
  ##
  public function set_revision()
  {
    if(_FCT_ANON_ARGS[0]) this.data.revision = _FCT_ANON_ARGS[0];
    else this.data.revision = 0;
  }
  
  ##
  # Base64s, timestamps, and appends data to the data.items array.
  ##
  public function append_data(name, data)
  {
    if(!name) name = _FCT_ANON_ARGS[0];
    if(!data) data = _FCT_ANON_ARGS[1];
    if(typeof_ex(data) == 'array' || typeof_ex(data) == 'list') data = base64(str:json_write(data));
    else if(typeof_ex(data) != 'int') data = base64(str:data);
    
    append_element(
      var:this.data.items, 
      value:{
        name:name, 
        data:data,
        timestamp: gettimeofday()
      }
    );
  }
  
  ##
  # Base64s and appends logs to the data.logs array.
  ##
  public function append_log(string)
  {
    if(!string)  string = _FCT_ANON_ARGS[0];
    
    append_element(var:this.data.logs, value:base64(str:string));
  }
  
  ##
  # Creates the tag name that data will be reported under.
  ##
  public function make_tag_name()
  {
    this.tag_name = strcat(
      'pd-', this.data.plugin_id, 
      '-', this.data.revision
    );
  }
  
  ##
  # Report the data to host tags
  ##
  private function report()
  {
    this.data.end_time = gettimeofday();
    
    report_xml_tag(
      tag:this.tag_name, 
      value:json_write(this.data)
    );
  }
}

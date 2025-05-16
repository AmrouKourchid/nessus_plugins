#TRUSTED 25359f411c3149a931cc9a1b2f0d91ecc622328b7e93c406daff2b639a5fccf9faf816ca05eaee6d587b33f8e83723d6b432c64e170e3e8ba85774aa62822ba068a4efcc8075e533ba765091f4c6caead1f04e11bdcc2051065ce7cc80291b7047a5e9d378764435af0aa40ef2bef722bd1d2ef6eb69f975b4ed1a6c81fbbd881a63cc27dd89617e5b7eb2bee27b259291c86c121d372da26f04ae6f13aba651ab81d52b6136aa9e25492e4c84a2383668fb59cdd77bb5c49044a2088c9670b9fc315b7ea193d2a8d1c3f54f2709361178ed16733dc6ea9499c362afd45b6147446f053525b2025718246e348ce1445e6b3c8c490d561b84940a6744d924599627ba9ebd9ce7a0e1e6fdd373f7ff846cdf78889d17259200952d549154c109fce0d2a4a6b339cc76ff5ad491f459a1bae4dde47514ad6c1d793998dc018ab9d890ccd3edf3b1fe62790b447ec42ba9f6a6faf8e865a3f85cb8262630c8310bb57f233950f9c3c11aea9440f334685d991d74e5e360f7550321956c163939d2107ac00e3f9a7aead7c3a6d61883e0addbd8386f258c53cefc8a17f4015a3a5caf6b781d931a3ad2602d6f7412f0353347013c118705fbdb65200cc9da3037b15ea4bce096c164569e0be67bd65711bc60cf486992add3e9ca6d25f759e9d0a227279d315caac169706774bcfc6b0f9a4e1800beb6cbe9267f5cc7104778d5f8a0
#TRUST-RSA-SHA256 507f4a4b44e375b97a46a46e423dcbd20c507378155b87d96947f878f6fcb44fe09d871e6afb80e2820c633b08caf8f814452431fe535330038b76d5c0709f8e1f1e6b3fa920ab595396211de1afed836af04db657d49df7d3905e59f7723f73af7272854a6c8af6e9394e0323af9ca1ede479af334254f3bd7376ca8fe6ba1c1f5a359c3113c07e3c4120fdf8c2418c439dd1b4aebb2d6c6b4161566fcfb30eff521fe354102973a01b717af7b91ecb8dabf024666a5ba80658b40f297905f6673c097b880fe51386980ff9ab0ffa3863cd1d68fca77135b3a108f5699400886ec8b105566708696e158a77cf7bfc8769e8a5928a979039435c311bd6c923e88c0c1fe33f2fc6f45b84e77757aace001770c1bf5ef78d545ad49f30a09842bbad8a5ac996538452e7b72aeff2d75a58bd46ca8690b05dd5fe803224eebf94dff6eb1d23f2902a832384b57896d4d155808df6194f006c3f9fcce9c62a379b8c6906b7fdb09887ceb4b46f9e6497d9b25e04f21caa5575552a1e40b9e630ed1d094918730b06d38b59630c1849bbac10b9bf0241ef914c74d529a3e22e7edb47619b1a603d0f33d9c655791e47547db6ad45fc4261503d7b4c3d2037b99f41407954f62a3af621b44e2bf272e8322e5ff963b552522568a8135f10b94c0183fb288c0bb707038c1c119c95a3df44eba98b0122bee3ea5c1ce42fac4b5b9d975c
##
# (C) Tenable, Inc.
##

include('compat_shared.inc');
include('debug.inc');
include('local_detection_nix.inc');

object php_ini_collector
{
  var main_ini;
  var additional_inis_path;

  ##
  # Constructor. Initializes the object with the main ini file and the path to the 
  # additional ini files.
  #
  # @param anon The arguments passed to the constructor.
  #   - main_ini: The path to the main ini file.
  #   - additional_inis_path: The path to the directory containing additional
  #     ini files.
  ##
  function php_ini_collector()
  {
    var args = _FCT_ANON_ARGS[0];
    this.main_ini = args.main_ini;
    this.additional_inis_path = args.additional_inis_path;
  }

  ##
  # Collects all the ini files and concatenates them into a single string.
  #
  # @return The contents of all the ini files.
  ##
  public function collect_and_concatenate_ini_files()
  {
    var contents = ldnix::get_file_contents(file:this.main_ini);

    foreach var ini_file (this.get_additional_ini_file_directory_listing())
      contents += ldnix::get_file_contents(file:ini_file);

    return contents;
  }

  ##
  # Gets a listing of all the additional ini files found in the additional ini
  # files directory. Only returns files that end in .ini.
  #
  # @return An array of additional ini files.
  ##
  function get_additional_ini_file_directory_listing()
  {
    var res = ldnix::run_cmd_template_wrapper(
      template : "ls -1 $1$/*.ini", 
      args     : [this.additional_inis_path]
    );

    var ini_files = this.clean_file_list(files:split(res, keep:FALSE));

    if(empty_or_null(ini_files))
      dbg::detailed_log(lvl:2, msg:'No additional ini files found.');
      
    return ini_files;
  }

  ##
  # Cleans the list of ini files by removing any files that do not end in .ini.
  #
  # @param ini_files The list of ini files to clean.
  #
  # @return The cleaned list of ini files.
  ##
  protected function clean_file_list(files)
  {
    var ret = [];

    foreach var file (files)
      if(file =~ ".*\.ini$") append_element(var:ret, value:file);

    return ret;
  }
}

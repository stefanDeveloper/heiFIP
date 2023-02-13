with import <nixpkgs> { };

let
  pythonPackages = python39Packages;
  pypyPackages = pypy3Packages;
in pkgs.mkShell rec {
  venvDir = "./.venv";
  requirements = "requirements.txt";

  name = "heiFIP";

  buildInputs = [
    pythonPackages.setuptools
    pythonPackages.virtualenv # run virtualenv .
    pythonPackages.pip
    pythonPackages.pyqt5 # avoid installing via pip
    # This execute some shell code to initialize a venv in $venvDir before
    # dropping into the shell
    pythonPackages.venvShellHook

    # Without setting the zlib in LD_LIBRARY_PATH we get the following error:
    # Original error was: libz.so.1: cannot open shared object file: No such file or directory
    zlib
  ];
  shellHook = ''
    # fixes libstdc++ issues and libgl.so issues
    LD_LIBRARY_PATH=${zlib}/lib/:${stdenv.cc.cc.lib}/lib/:/run/opengl-driver/lib/
    
    # fixes xcb issues :
    QT_PLUGIN_PATH=${qt5.qtbase}/${qt5.qtbase.qtPluginPrefix}
    SOURCE_DATE_EPOCH=$(date +%s)
    QT_XCB_GL_INTEGRATION="none"
    
    if [ -d "${venvDir}" ]; then
      echo "Skipping venv creation, '${venvDir}' already exists"
    else
      echo "Creating new venv environment in path: '${venvDir}'"
      # Note that the module venv was only introduced in python 3, so for 2.7
      # this needs to be replaced with a call to virtualenv
      ${pythonPackages.python.interpreter} -m venv "${venvDir}"
    fi

    # Under some circumstances it might be necessary to add your virtual
    # environment to PYTHONPATH, which you can do here too;
    PYTHONPATH=$PWD/${venvDir}/${pythonPackages.python.sitePackages}/:${pypy}:$PYTHONPATH
    
    source "${venvDir}/bin/activate"

    echo "Upgrading pip to latest version"
    python -m pip install --upgrade pip
    
    if [ -f "./${requirements}" ]; then
      echo "Install '${requirements}'"
      pip install -r ${requirements}
    fi

    pip install .
  '';
}
Electron-Cash, iOS Native UI
============================

This subdirectory implements an iOS native UI for Electron Cash, using UIKit via
'rubicon-ios' Python bindings. It uses the 'Briefcase' project to create an Xcode project which contains within it a Python interpreter, plus all scripts and dependent python packages.  Python 3.6 or above is recommended.

- Rubicon-iOS Web Page: https://pybee.org/project/projects/bridges/rubicon/
- Briefcase Web Page: https://pybee.org/project/projects/tools/briefcase/

Quick Start Instructions
------------------------
1. Requirements:

   * MacOS 10.11 or above is required with Xcode installed
   * Xcode >= 10.1 -- but *NOT* Xcode 11.x or above!
   * **IMPORTANT:** Do **not** use Xcode 11 or above. The app will not run correctly if you use this version of Xcode because Apple changed the ViewController API. See: https://medium.com/@hacknicity/view-controller-presentation-changes-in-ios-13-ac8c901ebc4e
   * MacPorts is required (Brew may work too but is untested)
   * Python 3.6 must be installed via either MacPorts or Brew
   * cookiecutter, briefcase, pbxproj, and setuptools python packages must be installed::

           python3 -m pip install 'setuptools==40.6.2' --user
           python3 -m pip install 'cookiecutter==1.6.0' --user
           python3 -m pip install 'briefcase==0.2.6' --user
           python3 -m pip install 'pbxproj==2.5.1' --user

           (NOTE: The exact versions specified above are known to work, but you may also try and use newer version as well.)

   * If you're using Brew, use pyenv to setup a Python 3.6 environment.

2. Generate the iOS project using the included shell script::

           ./make_ios_project.sh

3. Use Xcode to open the generated project, and add the following two libs (frameworks) to the project::

           libxml2.tbd

4. You may edit the python files in the Xcode project and build the app, etc.  Note that the python files in the app are copies of the files in the sourcecode repository. If you plan on committing changes back to the repository, use the included script to copy back changes::

           ./copy_back_changes.sh

App Store and Ad-Hoc Distribution
---------------------------------
For reasons that aren't entirely clear to me (but likely due to the way libPython.a and other libs are built), you need to do some special magic for the "Release" build to actually run properly. This means that if you want to compile for the App Store or for Ad-Hoc distribution, you need to disable symbol stripping of the compiled binary.  Make sure the following build settings for the "Release" build are as follows:

 - **Strip Debug Symbols During Copy** = NO
 - **Strip Linked Product** = NO
 - **Strip Style** = Debugging Symbols
 - **Enable Bitcode** = NO
 - **Valid Architectures** = arm64
 - **Symbols Hidden by Default** = NO

For more information, see this stackoverflow post: https://stackoverflow.com/questions/22261753/ios-app-wont-start-on-testflight-ad-hoc-distribution

Connecting to TestNet
---------------------
If you want to run the app to point to the BCH TestNet network:

  * Edit / Duplicate the Xcode "Scheme" for Electron Cash and set the envronment variable: `EC_TESTNET`


Additional Notes
----------------
The app built by this Xcode project is a fully running standalone Electron Cash as an iPhone app.  It pulls in sources from ../lib and other places when generating the Xcode project, but everything that is needed (.py files, Python interpreter, etc) ends up packaged in the generated iOS .app!

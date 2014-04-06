;--------------------------------
;Include Modern UI

  !include "MUI2.nsh"

;--------------------------------
;General

  ;Name and file
  Name "Electrum-Litecoin"
  OutFile "dist/electrum-setup.exe"

  ;Default installation folder
  InstallDir "$PROGRAMFILES\Electrum-Litecoin"

  ;Get installation folder from registry if available
  InstallDirRegKey HKCU "Software\Electrum-LTC" ""

  ;Request application privileges for Windows Vista
  RequestExecutionLevel admin

;--------------------------------
;Variables

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages

  ;!insertmacro MUI_PAGE_LICENSE "tmp/LICENCE"
  ;!insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_DIRECTORY

  ;Start Menu Folder Page Configuration
  !define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKCU"
  !define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\Electrum-LTC"
  !define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"

  ;!insertmacro MUI_PAGE_STARTMENU Application $StartMenuFolder

  !insertmacro MUI_PAGE_INSTFILES

  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES

;--------------------------------
;Languages

  !insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Installer Sections

Section

  SetOutPath "$INSTDIR"

  ;ADD YOUR OWN FILES HERE...
  file /r dist\electrum\*.*

  ;Store installation folder
  WriteRegStr HKCU "Software\Electrum-Litecoin" "" $INSTDIR

  ;Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"


  CreateShortCut "$DESKTOP\Electrum-Litecoin.lnk" "$INSTDIR\electrum-ltc.exe" ""

  ;create start-menu items
  CreateDirectory "$SMPROGRAMS\Electrum-Litecoin"
  CreateShortCut "$SMPROGRAMS\Electrum-Litecoin\Uninstall.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0
  CreateShortCut "$SMPROGRAMS\Electrum-Litecoin\Electrum-Litecoin.lnk" "$INSTDIR\electrum-ltc.exe" "" "$INSTDIR\electrum-ltc.exe" 0

SectionEnd

;--------------------------------
;Descriptions

  ;Assign language strings to sections
  ;!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  ;  !insertmacro MUI_DESCRIPTION_TEXT ${SecDummy} $(DESC_SecDummy)
  ;!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Section "Uninstall"

  ;ADD YOUR OWN FILES HERE...
  RMDir /r "$INSTDIR\*.*"

  RMDir "$INSTDIR"

  Delete "$DESKTOP\Electrum-Litecoin.lnk"
  Delete "$SMPROGRAMS\Electrum-Litecoin\*.*"
  RmDir  "$SMPROGRAMS\Electrum-Litecoin"

  DeleteRegKey /ifempty HKCU "Software\Electrum-LTC"

SectionEnd

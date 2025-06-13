;--------------------------------
;Include Modern UI
  !include "TextFunc.nsh" ;Needed for the $GetSize function. I know, doesn't sound logical, it isn't.
  !include "MUI2.nsh"

;--------------------------------
;Variables

  !define PRODUCT_NAME "Electrum"
  !define PRODUCT_WEB_SITE "https://github.com/spesmilo/electrum"
  !define PRODUCT_PUBLISHER "Electrum Technologies GmbH"
  !define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

;--------------------------------
;General

  ;Name and file
  Name "${PRODUCT_NAME}"
  OutFile "dist/electrum-setup.exe"

  ;Default installation folder
  InstallDir "$PROGRAMFILES64\${PRODUCT_NAME}"

  ;Get installation folder from registry if available
  InstallDirRegKey HKCU "Software\${PRODUCT_NAME}" ""

  ;Request application privileges for Windows Vista
  RequestExecutionLevel admin

  ;Specifies whether or not the installer will perform a CRC on itself before allowing an install
  CRCCheck on

  ;Sets whether or not the details of the install are shown. Can be 'hide' (the default) to hide the details by default, allowing the user to view them, or 'show' to show them by default, or 'nevershow', to prevent the user from ever seeing them.
  ShowInstDetails show

  ;Sets whether or not the details of the uninstall  are shown. Can be 'hide' (the default) to hide the details by default, allowing the user to view them, or 'show' to show them by default, or 'nevershow', to prevent the user from ever seeing them.
  ShowUninstDetails show

  ;Sets the colors to use for the install info screen (the default is 00FF00 000000. Use the form RRGGBB (in hexadecimal, as in HTML, only minus the leading '#', since # can be used for comments). Note that if "/windows" is specified as the only parameter, the default windows colors will be used.
  InstallColors /windows

  ;This command sets the compression algorithm used to compress files/data in the installer. (http://nsis.sourceforge.net/Reference/SetCompressor)
  SetCompressor /SOLID lzma

  ;Sets the dictionary size in megabytes (MB) used by the LZMA compressor (default is 8 MB).
  SetCompressorDictSize 64

  ;Sets the text that is shown (by default it is 'Nullsoft Install System vX.XX') in the bottom of the install window. Setting this to an empty string ("") uses the default; to set the string to blank, use " " (a space).
  BrandingText "${PRODUCT_NAME} Installer v${PRODUCT_VERSION}"

  ;Sets what the titlebars of the installer will display. By default, it is 'Name Setup', where Name is specified with the Name command. You can, however, override it with 'MyApp Installer' or whatever. If you specify an empty string (""), the default will be used (you can however specify " " to achieve a blank string)
  Caption "${PRODUCT_NAME}"

  ;Adds the Product Version on top of the Version Tab in the Properties of the file.
  VIProductVersion 1.0.0.0

  ;VIAddVersionKey - Adds a field in the Version Tab of the File Properties. This can either be a field provided by the system or a user defined field.
  VIAddVersionKey ProductName "${PRODUCT_NAME} Installer"
  VIAddVersionKey Comments "The installer for ${PRODUCT_NAME}"
  VIAddVersionKey CompanyName "${PRODUCT_NAME}"
  VIAddVersionKey LegalCopyright "2013-2018 ${PRODUCT_PUBLISHER}"
  VIAddVersionKey FileDescription "${PRODUCT_NAME} Installer"
  VIAddVersionKey FileVersion ${PRODUCT_VERSION}
  VIAddVersionKey ProductVersion ${PRODUCT_VERSION}
  VIAddVersionKey InternalName "${PRODUCT_NAME} Installer"
  VIAddVersionKey LegalTrademarks "${PRODUCT_NAME} is a trademark of ${PRODUCT_PUBLISHER}"
  VIAddVersionKey OriginalFilename "${PRODUCT_NAME}.exe"

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING
  !define MUI_ABORTWARNING_TEXT "Are you sure you wish to abort the installation of ${PRODUCT_NAME}?"

  !define MUI_ICON "..\..\electrum\gui\icons\electrum.ico"

;--------------------------------
;Pages

  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES

;--------------------------------
;Languages

  !insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Functions

!macro CreateEnsureNotRunning prefix operation

Function ${prefix}EnsureNotRunning
  ; pop the directory to check from the stack into $R0
  Pop $R0
  ; if the dir at $R0 doesn't exist, jump to nodir
  IfFileExists "$R0" 0 nodir
    ; Find all .exe files in the directory, $1 is the handle, $2 is the filename
    FindFirst $1 $2 "$R0\*.exe"
    IfErrors noexe 0

    checkloop:
    ; Skip checking the uninstaller if we are the uninstaller to avoid locking the uninstaller itself
    !if "${prefix}" == "un."
        StrCmp $2 "Uninstall.exe" skipfile 0
    !endif

    ; Check if we can append to the .exe file. If we can't that means it is still running.
    retryopen:
    FileOpen $0 "$R0\$2" a
    IfErrors 0 closeexe
      MessageBox MB_RETRYCANCEL "Can not ${operation} because $2 is still running. Close it and retry." /SD IDCANCEL IDRETRY retryopen
      FindClose $1
      Abort
    closeexe:
    FileClose $0

    skipfile:
    ; Find next .exe file
    FindNext $1 $2
    IfErrors done 0
    Goto checkloop

    done:
    FindClose $1

  noexe:
  nodir:
FunctionEnd

!macroend

; The function has to be created twice, once for the installer and once for the uninstaller
!insertmacro CreateEnsureNotRunning "" "install"
!insertmacro CreateEnsureNotRunning "un." "uninstall"

;--------------------------------
;Installer Sections

;Check if we have Administrator rights
Function .onInit
	UserInfo::GetAccountType
	pop $0
	${If} $0 != "admin" ;Require admin rights on NT4+
		MessageBox mb_iconstop "Administrator rights required!"
		SetErrorLevel 740 ;ERROR_ELEVATION_REQUIRED
		Quit
	${EndIf}

  ; Check if already installed and ensure the process is not running if it is
  ReadRegStr $R0 HKCU "Software\${PRODUCT_NAME}" ""
  IfErrors noinstdir 0
    Push $R0
    Call EnsureNotRunning
  noinstdir:
  ClearErrors
FunctionEnd

Section
  SetOutPath $INSTDIR

  ;Uninstall previous version files
  RMDir /r "$INSTDIR\*.*"
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\*.*"

  ;Files to pack into the installer
  File /r "dist\electrum\*.*"
  File "..\..\electrum\gui\icons\electrum.ico"

  ;Store installation folder
  WriteRegStr HKCU "Software\${PRODUCT_NAME}" "" $INSTDIR

  ;Create uninstaller
  DetailPrint "Creating uninstaller..."
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ;Create desktop shortcut
  DetailPrint "Creating desktop shortcut..."
  CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\electrum-${PRODUCT_VERSION}.exe" ""

  ;Create start-menu items
  DetailPrint "Creating start-menu items..."
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\electrum-${PRODUCT_VERSION}.exe" "" "$INSTDIR\electrum-${PRODUCT_VERSION}.exe" 0
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME} Testnet.lnk" "$INSTDIR\electrum-${PRODUCT_VERSION}.exe" "--testnet" "$INSTDIR\electrum-${PRODUCT_VERSION}.exe" 0


  ;Links bitcoin: and lightning: URIs to Electrum
  WriteRegStr HKCU "Software\Classes\bitcoin" "" "URL:bitcoin Protocol"
  WriteRegStr HKCU "Software\Classes\bitcoin" "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\bitcoin" "DefaultIcon" "$\"$INSTDIR\electrum.ico, 0$\""
  WriteRegStr HKCU "Software\Classes\bitcoin\shell\open\command" "" "$\"$INSTDIR\electrum-${PRODUCT_VERSION}.exe$\" $\"%1$\""
  WriteRegStr HKCU "Software\Classes\lightning" "" "URL:lightning Protocol"
  WriteRegStr HKCU "Software\Classes\lightning" "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\lightning" "DefaultIcon" "$\"$INSTDIR\electrum.ico, 0$\""
  WriteRegStr HKCU "Software\Classes\lightning\shell\open\command" "" "$\"$INSTDIR\electrum-${PRODUCT_VERSION}.exe$\" $\"%1$\""

  ;Adds an uninstaller possibility to Windows Uninstall or change a program section
  WriteRegStr HKCU "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr HKCU "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKCU "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr HKCU "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKCU "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\electrum.ico"

  ;Fixes Windows broken size estimates
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKCU "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"
SectionEnd

;--------------------------------
;Descriptions

;--------------------------------
;Uninstaller Section

Section "Uninstall"
  RMDir /r "$INSTDIR\*.*"

  RMDir "$INSTDIR"

  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\*.*"
  RMDir  "$SMPROGRAMS\${PRODUCT_NAME}"

  DeleteRegKey HKCU "Software\Classes\bitcoin"
  DeleteRegKey HKCU "Software\${PRODUCT_NAME}"
  DeleteRegKey HKCU "${PRODUCT_UNINST_KEY}"
SectionEnd

Function UN.onInit
  ; Ensure the process is not running in the uninstallation directory
  Push $INSTDIR
  Call un.EnsureNotRunning
FunctionEnd

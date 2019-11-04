package eu.vin.joseserver.view;

import eu.vin.joseserver.controller.Jose4jAdapter;
import org.apache.commons.codec.binary.Base64;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Jose4jHandler extends AbstractHandler {
    private Jose4jAdapter adapter256 = Jose4jAdapter.getInstance256();
    private Jose4jAdapter adapter384 = Jose4jAdapter.getInstance384();
    private Jose4jAdapter adapter521 = Jose4jAdapter.getInstance521();
    private int i = 0;

    public Jose4jHandler() {

    }

    @Override
    public void handle(String s, Request request, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ServletException {
//        System.out.println(++i);
        httpServletResponse.setContentType("text/html; charset=utf-8");
        String token = request.getParameter("token");
        JSONObject jsonHeader;
        JSONObject jsonJWK;
        String curve = "";
        if (token == null) curve = "";
        else {
            try {
                jsonHeader = (JSONObject) new JSONParser().parse(new String(Base64.decodeBase64(token.split("\\.")[0])));
                jsonJWK = (JSONObject) jsonHeader.get("epk");
                curve = jsonJWK.get("crv").toString();
            } catch (ParseException e) {
                e.printStackTrace();
            }
        }
        switch (curve) {
            case "P-256":
                try {
                    httpServletResponse.getWriter().println(adapter256.processJWE(token));
                    httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                } catch (Exception e) {
                    // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
                    // Hopefully with meaningful explanations(s) about what went wrong.
                    //e.printStackTrace();
                    httpServletResponse.getWriter().println(e.getMessage());
                    httpServletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
                break;
            case "P-384":
                try {
                    httpServletResponse.getWriter().println(adapter384.processJWE(token));
                    httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                } catch (Exception e) {
                    // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
                    // Hopefully with meaningful explanations(s) about what went wrong.
                    //e.printStackTrace();
                    httpServletResponse.getWriter().println("Invalid JWT! " + e);
                    httpServletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
                break;
            case "P-521":
                try {
                    httpServletResponse.getWriter().println(adapter521.processJWE(token));
                    httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                } catch (Exception e) {
                    // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
                    // Hopefully with meaningful explanations(s) about what went wrong.
                    //e.printStackTrace();
                    httpServletResponse.getWriter().println(e.getCause().toString());
                    httpServletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
                break;
            default:
                httpServletResponse.getWriter().println("Please provide JWE in parameter token");
                httpServletResponse.setStatus(HttpServletResponse.SC_OK);
        }

        request.setHandled(true);
    }
}

package eu.vin.joseserver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

import eu.vin.joseserver.controller.Jose4jAdapter;
import eu.vin.joseserver.controller.NimbusAdapter;
import eu.vin.joseserver.view.Jose4jHandler;
import eu.vin.joseserver.view.NimbusHandler;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;

public class PublicKeyIssuer extends AbstractHandler {
    private static Jose4jAdapter  adapter256 = Jose4jAdapter.getInstance256();
    private static Jose4jAdapter  adapter384 = Jose4jAdapter.getInstance384();
    private static Jose4jAdapter  adapter521 = Jose4jAdapter.getInstance521();
    private static NimbusAdapter  adapterNimbus256 = NimbusAdapter.getInstance256();
    private static NimbusAdapter  adapterNimbus384 = NimbusAdapter.getInstance384();
    private static NimbusAdapter  adapterNimbus521 = NimbusAdapter.getInstance521();


    public PublicKeyIssuer() {}

    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=utf-8");
        response.setStatus(HttpServletResponse.SC_OK);
        baseRequest.setHandled(true);

        PrintWriter out = response.getWriter();
        out.println("<p>jose4j Curve P-256 public key:<br>" + adapter256.getPublicKeyJweHeader() + "</p>");
        out.println("<p>jose4j Curve P-384 public key:<br>" + adapter384.getPublicKeyJweHeader() + "</p>");
        out.println("<p>jose4j Curve P-521 public key:<br>" + adapter521.getPublicKeyJweHeader() + "</p>");
        out.println("<p>Nimbus Curve P-256 public key:<br>" + adapterNimbus256.getPublicKeyJweHeader() + "</p>");
        out.println("<p>Nimbus Curve P-384 public key:<br>" + adapterNimbus384.getPublicKeyJweHeader() + "</p>");
        out.println("<p>Nimbus Curve P-521 public key:<br>" + adapterNimbus521.getPublicKeyJweHeader() + "</p>");

    }

    public static void main(String[] args) throws Exception {
        Server server = new Server(8081);
        ContextHandler indexHandler = new ContextHandler("/");
        indexHandler.setHandler(new PublicKeyIssuer());

        ContextHandler jose4jContextHandler = new ContextHandler("/jose4j");
        jose4jContextHandler.setHandler(new Jose4jHandler());

        ContextHandler nimbusContextHandler = new ContextHandler("/nimbus");
        nimbusContextHandler.setHandler(new NimbusHandler());

        ContextHandlerCollection contexts = new ContextHandlerCollection();
        contexts.setHandlers(new Handler[] { indexHandler, jose4jContextHandler, nimbusContextHandler });
        server.setHandler(contexts);
        server.start();
        server.join();
    }
}


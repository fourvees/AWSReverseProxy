
package in.fourvees.nio.aws.proxy;

import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import com.amazonaws.auth.AWSCredentialsProvider;

import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.HeaderMap;
import io.undertow.util.HeaderValues;
import io.undertow.util.HttpString;

public class BasicAuthHandler implements HttpHandler {

    private final HttpHandler next; 
    private final Set<String> authentications = new HashSet<String>();
    private final Properties prop;
    private final AWSCredentialsProvider cre;
    private final Map<String, Object> users;

    public BasicAuthHandler(Map<String, Object> users, HttpHandler next,Properties prop,AWSCredentialsProvider cre) {
        this.next = next;
        this.prop=prop;
        this.cre=cre;
        this.users = users;
        
        for(String key : users.keySet())
   	 	{		 
	   		 Map<String,Object> g = (Map<String,Object>) users.get(key);	   		 
	   		 String f = key + ":" + g.get("cred").toString();	   		
	   		 byte[] auth = Base64.getEncoder().encode(f.getBytes());
	   		 authentications.add("Basic " + new String(auth));	   		 		 
   	 	}
                          
    }

    @Override
    public void handleRequest(HttpServerExchange req) throws Exception {
        String auth = req.getRequestHeaders().getFirst("Authorization");        
        if(authentications.contains(auth)) {
        	
        	InetSocketAddress peer = req.getSourceAddress();
        	auth = auth.replace("Basic ","");
        	byte[] decoded = Base64.getDecoder().decode(auth.getBytes());
        	String userName = new String(decoded).split(":")[0];
        	        	
        	Map<String,Object> g = (Map<String,Object>) users.get(userName);
        	List<String> rules = (List<String>) g.get("allow");
        	boolean allow=false;
        	
        	for(String prefix : rules)
        	{
        		if(req.getRequestURI().startsWith(prefix))
        		{
        			allow = true;
        			break;
        		}
        	}
        	
        	if(allow)
        	{        		
        		AWSLogger.getInstance(prop, cre).log("Authorized Access for user " + userName + " from " + peer.getAddress().getHostAddress() + ":" + peer.getPort()  + " for " + req.getRequestURL());
        		next.handleRequest(req);
        	}
        	else
        	{        		
        		AWSLogger.getInstance(prop, cre).log("Unauthorized Access for user " + userName  + " from " + peer.getAddress().getHostAddress() + ":" + peer.getPort()  + " for " + req.getRequestURL());
        		req.setStatusCode(403);
        		req.getResponseSender().send("Unauthorized access requested for user " + userName);    
        	}
        } else {
        	InetSocketAddress peer = req.getSourceAddress();        	 
        	AWSLogger.getInstance(prop, cre).log("Unauthorized Access from " + peer.getAddress().getHostAddress() + ":" + peer.getPort()  + " for " + req.getRequestURL());
        	
        	HeaderMap hh = req.getRequestHeaders();
    		    		
    		long f = hh.fastIterateNonEmpty();
            HeaderValues values;
            
            while (f != -1L) {
                values = hh.fiCurrent(f);
                AWSLogger.getInstance(prop, cre).log(values.getHeaderName().toString().toLowerCase() + ":" + hh.getFirst((values.getHeaderName().toString())));                
                f = hh.fiNextNonEmpty(f);
            }
        	                       
            req.setStatusCode(401);
            req.getResponseHeaders().put(new HttpString("WWW-Authenticate"), "Basic realm=AWSV4SignProxy");
            req.getResponseSender().send("Unauthorized");            
        }
    }
}
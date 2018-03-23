
package in.fourvees.nio.aws.proxy;

import io.undertow.server.DefaultResponseListener;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;

public class ResponseHandler implements HttpHandler {

	public ResponseHandler() {
        
    }

    @Override
    public void handleRequest(HttpServerExchange req) throws Exception {
    	System.out.println("RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR");
    	req.addDefaultResponseListener(responseListener);
    }
    
    private final DefaultResponseListener responseListener = new DefaultResponseListener() {
        @Override
        public boolean handleDefaultResponse(final HttpServerExchange exchange) {
        	System.out.println("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG");
            if (!exchange.isResponseChannelAvailable()) {
            	System.out.println(exchange.getStatusCode());
                return false;
            }
            System.out.println(exchange.getStatusCode());
            return false;
        }
    };

}
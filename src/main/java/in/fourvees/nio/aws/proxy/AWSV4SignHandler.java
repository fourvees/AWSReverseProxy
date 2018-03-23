package in.fourvees.nio.aws.proxy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacUtils;
import org.xnio.ChannelListener;
import org.xnio.IoUtils;
import org.xnio.channels.StreamSourceChannel;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;

import io.undertow.UndertowLogger;
import io.undertow.connector.PooledByteBuffer;
import io.undertow.server.Connectors;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.proxy.ProxyHandler;
import io.undertow.server.protocol.http.HttpContinue;
import io.undertow.util.HeaderMap;
import io.undertow.util.HeaderValues;
import io.undertow.util.HttpString;

public class AWSV4SignHandler implements HttpHandler  {

	private final ProxyHandler next;
	private final String awsService;
	private final String awsRegion;
	private final int maxBuffers;
	private final AWSCredentials awsCred;
	private final AWSCredentialsProvider cre;
	
		
	public AWSV4SignHandler(ProxyHandler next,String awsService,String awsRegion,int maxBuffers,AWSCredentialsProvider cre) {
		 this.next = next;
		 this.awsService = awsService;
		 this.awsRegion = awsRegion;
		 this.maxBuffers = maxBuffers;
		 this.cre = cre;
		 this.awsCred  = cre.getCredentials();		 
	}
	
	@Override
	public void handleRequest(HttpServerExchange arg0) throws Exception {

		ZonedDateTime zonedDateTime = ZonedDateTime.now(ZoneOffset.UTC);
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
		DateTimeFormatter formatter1 = DateTimeFormatter.ofPattern("yyyyMMdd");
				
		String cannonicalReq = arg0.getRequestMethod() + "\n";
		
		String uri[] = arg0.getRequestURI().split("/");
		String reqUri="/";
		
		for(String u : uri)
		{
			if(reqUri.equals("/"))
				reqUri = reqUri +  encode(u);
			else
				reqUri = reqUri + "/" + encode(u);
		}
		
		if(arg0.getRequestURI().endsWith("/"))
			reqUri = reqUri + "/";
		
		cannonicalReq = cannonicalReq + reqUri + "\n" ;
		
		Map<String,Deque<String>> hm = new  HashMap<String,Deque<String>>();
		hm = arg0.getQueryParameters();		
		
		String cannQuery ="";
		
		List<String> cc = new ArrayList<String>();
		
		for(String key : hm.keySet())
		{
			cc.add(key);
		}
		
		 Collections.sort(cc);
		 //Collections.reverse(cc);
		
		for(String key : cc)
		{
			if(cannQuery.length()==0)
				cannQuery = key + "=" + encode(hm.get(key).pop());
			else
				cannQuery = cannQuery + "&" + key + "=" + encode(hm.get(key).pop());
							
		}
		
		//System.out.println(cannQuery);
													
		HeaderMap hh = arg0.getRequestHeaders();
		List<String> d = new ArrayList<String>();
		
		long f = hh.fastIterateNonEmpty();
        HeaderValues values;
        
        while (f != -1L) {
            values = hh.fiCurrent(f);
            d.add(values.getHeaderName().toString().toLowerCase());  
            f = hh.fiNextNonEmpty(f);
        }
        
        Collections.sort(d);
        String cannHead="";
        String canHead2="";
        for(String s : d)
        {        	        		
        		if(s.equalsIgnoreCase("content-type"))
        		{
        			cannHead = cannHead + s.toLowerCase() + ":" + hh.get(s).getFirst().trim() + "\n";
        			canHead2 = canHead2 + s.toLowerCase() + ";";
        		}
        		else if(s.equalsIgnoreCase("host"))
        		{
        			String host="";        			
        			if(hh.get(s).getFirst().trim().contains(":"))
        			{
        				String af[] = hh.get(s).getFirst().trim().split(":");
        				host = af[0];
        			}else
        				host = hh.get(s).getFirst().trim();
        			cannHead = cannHead + s.toLowerCase() + ":" + host + "\n";
        			canHead2 = canHead2 + s.toLowerCase() + ";";
        		}
        }
        
        cannHead = cannHead + "x-amz-date" + ":" + zonedDateTime.format(formatter) + "\n\n";
        canHead2 = canHead2 + "x-amz-date\n";
		
        //System.out.println(cannHead);
		//System.out.println(canHead2);
							
		//System.out.println("Request Body " + getRequestBody(arg0,maxBuffers));	
		//System.out.println(arg0.getRequestContentLength());
		
		String payload = getRequestBody(arg0,maxBuffers);
		//System.out.println("PayLoad " + payload);
		String payloadHash = DigestUtils.sha256Hex(payload);
		//System.out.println("PayLoad Hash " + payloadHash);
		
		
		cannonicalReq = cannonicalReq + cannQuery + "\n";
		
		cannonicalReq = cannonicalReq + cannHead;
		
		cannonicalReq = cannonicalReq + canHead2;
		
		cannonicalReq = cannonicalReq + payloadHash;
		
		String cannonicalReqHash = DigestUtils.sha256Hex(cannonicalReq);
		
		//System.out.println(cannonicalReq);
		//System.out.println(cannonicalReqHash);
		
		String signString = "AWS4-HMAC-SHA256\n";
				
		String reqDateTime = zonedDateTime.format(formatter);
				
		String credentialScope = zonedDateTime.format(formatter1) + "/" + awsRegion + "/" + awsService + "/aws4_request\n";
		
		signString = signString + reqDateTime + "\n";
		
		signString = signString + credentialScope;
		
		signString = signString + cannonicalReqHash;
		
		 //System.out.println(signString);
				 
		 String secretAccess = awsCred.getAWSSecretKey();
		 		 
		 String key = "AWS4" + secretAccess;
		 
		 byte[] kDate   = HmacUtils.hmacSha256(key, zonedDateTime.format(formatter1));
		 
		 byte[] kRegion = HmacUtils.hmacSha256(kDate, awsRegion.getBytes());
		 
		 byte[] kService = HmacUtils.hmacSha256(kRegion, awsService.getBytes());
		 
		 byte[] kSigning  = HmacUtils.hmacSha256(kService, "aws4_request".getBytes());
		
		 Hex hex = new Hex();
		 
		 String hexkSign = hex.encodeHexString(kSigning);
		 
		 String signature  = HmacUtils.hmacSha256Hex(kSigning,signString.getBytes());
		
		 //System.out.println("Signature " + signature);
		 
		 String credStr = "Credential=" + awsCred.getAWSAccessKeyId() + "/" + credentialScope + ", SignedHeaders=" + canHead2 + ", Signature=" + signature;
		 
		 //System.out.println(credStr);
		 
		 HttpString h = new HttpString("Authorization");
		 		 		
		 next.addRequestHeader(h, "AWS4-HMAC-SHA256 " + credStr);
		 
		 HttpString hd = new HttpString("X-Amz-Date");
	 		
		 next.addRequestHeader(hd,zonedDateTime.format(formatter));
				
		 next.handleRequest(arg0);
		
	}
	
	public String getRequestBody(HttpServerExchange arg0,int maxBuffers) throws Exception
	{
		String requestBody = "";
        if(!arg0.isRequestComplete() && !HttpContinue.requiresContinueResponse(arg0.getRequestHeaders())) {
            final StreamSourceChannel channel = arg0.getRequestChannel();
            int readBuffers = 0;
            final PooledByteBuffer[] bufferedData = new PooledByteBuffer[maxBuffers];
            PooledByteBuffer buffer = arg0.getConnection().getByteBufferPool().allocate();
           
            
            try {
                do {
                    int r;
                    ByteBuffer b = buffer.getBuffer();
                    r = channel.read(b);
                                                           
                    if (r == -1) { //TODO: listener read
                        if (b.position() == 0) {
                            buffer.close();
                        } else {
                            b.flip();
                            bufferedData[readBuffers] = buffer;
                        }
                        break;
                    } else if (r == 0) {
                        final PooledByteBuffer finalBuffer = buffer;
                        final int finalReadBuffers = readBuffers;
                        channel.getReadSetter().set(new ChannelListener<StreamSourceChannel>() {

                            PooledByteBuffer buffer = finalBuffer;
                            int readBuffers = finalReadBuffers;

                            @Override
                            public void handleEvent(StreamSourceChannel channel) {
                                try {
                                    do {
                                        int r;
                                        ByteBuffer b = buffer.getBuffer();
                                        r = channel.read(b);
                                        if (r == -1) { //TODO: listener read
                                            if (b.position() == 0) {
                                                buffer.close();
                                            } else {
                                                b.flip();
                                                bufferedData[readBuffers] = buffer;
                                            }
                                            Connectors.ungetRequestBytes(arg0, bufferedData);
                                            Connectors.resetRequestChannel(arg0);
                                            Connectors.executeRootHandler(next, arg0);
                                            channel.getReadSetter().set(null);
                                            return;
                                        } else if (r == 0) {
                                            return;
                                        } else if (!b.hasRemaining()) {
                                            b.flip();
                                            bufferedData[readBuffers++] = buffer;
                                            if (readBuffers == maxBuffers) {
                                                Connectors.ungetRequestBytes(arg0, bufferedData);
                                                Connectors.resetRequestChannel(arg0);
                                                Connectors.executeRootHandler(next, arg0);
                                                channel.getReadSetter().set(null);
                                                return;
                                            }
                                            buffer = arg0.getConnection().getByteBufferPool().allocate();
                                        }
                                    } while (true);
                                } catch (Throwable t) {
                                    if (t instanceof IOException) {
                                        UndertowLogger.REQUEST_IO_LOGGER.ioException((IOException) t);
                                    } else {
                                        UndertowLogger.REQUEST_IO_LOGGER.handleUnexpectedFailure(t);
                                    }
                                    for (int i = 0; i < bufferedData.length; ++i) {
                                        IoUtils.safeClose(bufferedData[i]);
                                    }
                                    if (buffer != null && buffer.isOpen()) {
                                        IoUtils.safeClose(buffer);
                                    }
                                    arg0.endExchange();
                                }
                            }
                        });
                        channel.resumeReads();
                        return "";
                    } else if (!b.hasRemaining()) {
                        b.flip();
                        bufferedData[readBuffers++] = buffer;                                               
                        if (readBuffers == maxBuffers) {
                            break;
                        }
                        buffer = arg0.getConnection().getByteBufferPool().allocate();
                    }
                   
                  b.flip();
                  while(b.hasRemaining())
                  {
                	  requestBody = requestBody + (char) b.get();
                  }
                    
                } while (true);
                Connectors.ungetRequestBytes(arg0, bufferedData);
                Connectors.resetRequestChannel(arg0);
            } catch (Exception | Error e) {
                for (int i = 0; i < bufferedData.length; ++i) {
                    IoUtils.safeClose(bufferedData[i]);
                }
                if (buffer != null && buffer.isOpen()) {
                    IoUtils.safeClose(buffer);
                }
                throw e;
            }
        }
                
        return requestBody;
        
	}
	
	
	public static String encode(String str) throws Exception
	{
		String rtn = URLEncoder.encode(str, "UTF-8");
		rtn = rtn.replaceAll("\\+", "%20");		
		rtn = rtn.replaceAll("\\*", "%2A");

		return rtn;
	}
	

	}


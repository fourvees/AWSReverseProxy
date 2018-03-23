package in.fourvees.nio.aws.proxy;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.Xnio;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.PropertiesFileCredentialsProvider;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.google.gson.Gson;

import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.protocols.ssl.UndertowXnioSsl;
import io.undertow.server.HttpHandler;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.handlers.proxy.LoadBalancingProxyClient;
import io.undertow.server.handlers.proxy.ProxyHandler;

public class ReverseProxy {

	private static final Logger log = LogManager.getLogger(ReverseProxy.class);
	
	public static void main(String a[]) throws Exception
	{

	  if(a.length==0)
	  {
		  msg();
	  }
		
	  Properties prop = new Properties();
	  FileInputStream in = new FileInputStream(a[0]);
	  prop.load(in);
	  in.close();
	  	 	  
	  String keyStorePath = prop.getProperty("keyStorePath","proxystore");
	  String keyStorePass = prop.getProperty("keyStorePass","welcome");
	  String trustStorePath = prop.getProperty("trustStorePath","cacerts");
	  String trustStorePass = prop.getProperty("trustStorePass","changeit");
	  String awsCredProvider = prop.getProperty("awsCredProvider","auto");
	  String awsService = prop.getProperty("awsService","es");
	  String awsRegion  = prop.getProperty("awsRegion","eu-west-2");
	  String maxBuffers = prop.getProperty("maxBuffers","100");
	  String totalBackends = prop.getProperty("totalBackends","1");
	  String bindAddress = prop.getProperty("bindAddress","0.0.0.0");
	  int httpPort =  Integer.parseInt(prop.getProperty("httpPort","80"));
	  int httpsPort =  Integer.parseInt(prop.getProperty("httpsPort","443"));
	  int maxRequestTime = Integer.parseInt(prop.getProperty("maxRequestTime","30000"));
      int connectionsPerThread = Integer.parseInt(prop.getProperty("connectionsPerThread","20"));
      int ioThreads = Integer.parseInt(prop.getProperty("ioThreads","4"));
      int workerThreads = Integer.parseInt(prop.getProperty("workerThreads",String.valueOf(Runtime.getRuntime().availableProcessors() * 8)));
      int workerTaskMaxThreads = Integer.parseInt(prop.getProperty("workerTaskMaxThreads",String.valueOf(workerThreads)));      
      String authS3Region = prop.getProperty("auth.s3Region");
      String authS3Json = prop.getProperty("auth.s3JsonFile");
      	  		  
	  KeyStore keyStore = loadKeyStore(keyStorePath, keyStorePass);
	  KeyStore trustStore = loadKeyStore(trustStorePath, trustStorePass);
      SSLContext sslContext = newSslContext(keyStore, keyStorePass,trustStore,trustStorePass);
      AWSCredentialsProvider cre = null;
                
      if(!awsCredProvider.equalsIgnoreCase("auto"))
    	  cre = new PropertiesFileCredentialsProvider(awsCredProvider);
      else
    	  cre = DefaultAWSCredentialsProviderChain.getInstance();
      
      AWSCredentials cred = cre.getCredentials();
      		
	 Undertow undertow;
	 
	 int totalNoBackend = Integer.parseInt(totalBackends);
			 
	 PathHandler handler = Handlers.path();
	 
	 AWSLogger.getInstance(prop, cre).log("Java NIO Reverse Proxy");
	 
	 AmazonS3 s3Client = AmazonS3ClientBuilder.standard().withCredentials(cre).withRegion(authS3Region).build();
	 
	 String s3[] = authS3Json.replace("s3://", "").split("/");
	 String keyPath="";
		for(int i=1;i<s3.length;i++){
			if(s3[i].length()>0)
				keyPath = keyPath + s3[i] + "/";
		}
	keyPath = keyPath.substring(0, keyPath.length()-1);
	String json = s3Client.getObjectAsString(s3[0], keyPath);
	  
	 Map<String,Object> bas = new Gson().fromJson(json, Map.class);
	 
		 	 	 
	 for(int i=1;i<=totalNoBackend;i++)
	 {
		 
		 String proxyPrefix = "proxy.prefix." + i;
		 String proxyHosts = "proxy.hosts." + i;
	 
		 if(null!=prop.getProperty(proxyPrefix) && null!=prop.getProperty(proxyHosts))
		 {
			 
			 String hosts[] = prop.getProperty(proxyHosts).split(",");
			 
			 LoadBalancingProxyClient loadBalancer = new LoadBalancingProxyClient()
		             .setConnectionsPerThread(connectionsPerThread);
			 
			 ResponseHandler resp = new ResponseHandler();
			 
			 ProxyHandler proxyHandler = ProxyHandler.builder().setProxyClient(loadBalancer).setMaxRequestTime(maxRequestTime).setNext(resp).build(); 
			 
			 HttpHandler awsSignHandler = new AWSV4SignHandler(proxyHandler,awsService,awsRegion,Integer.parseInt(maxBuffers),cre);
			 			 			 						 
			 BasicAuthHandler basicAuth = new  BasicAuthHandler(bas, awsSignHandler,prop,cre);
			 
			 for(String s : hosts)
			 {
				 loadBalancer.addHost(new URI("https://" + s),new UndertowXnioSsl(Xnio.getInstance(), OptionMap.EMPTY, sslContext));
			 }
			 	              
			 handler.addPrefixPath(prop.getProperty(proxyPrefix), basicAuth);
		 }
	 
	 }
	 
	 Undertow.Builder proxyBuilder = Undertow.builder()        
			 .setIoThreads(ioThreads)
             .setWorkerThreads(workerThreads)
             .setWorkerOption(Options.WORKER_TASK_MAX_THREADS, workerTaskMaxThreads)
             .setSocketOption(Options.BACKLOG, 1000)
             .setHandler(handler);            
	 
	 //proxyBuilder.addHttpListener(httpPort, bindAddress);
	 proxyBuilder.addHttpsListener(httpsPort, bindAddress, sslContext);
	 
	 undertow = proxyBuilder.build();
	 	 	 
	 undertow.start();
	 
	 log.info("Reverse proxy server listening for SSL connections on " + bindAddress + ":" + httpsPort);
	 	 	 	 	 	 
	}
	
	public static SSLContext newSslContext(final KeyStore keyStore, String keyStorePw,final KeyStore trustStore, String trustStorePw) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyStorePw.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
        
        TrustManager[] trustManagers;
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        trustManagers = trustManagerFactory.getTrustManagers();


        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, trustManagers, null);

        return sslContext;
    }

    public static KeyStore loadKeyStore(String storeLoc, String storePw) throws Exception {
    	Path p = Paths.get(storeLoc);
    	InputStream stream = null;
    	    	
    	if(Files.exists(p))    	
    		stream = Files.newInputStream(p);
    	else
    		stream = ReverseProxy.class.getResourceAsStream("/"+storeLoc);
    	
        if(stream == null) {
            throw new IllegalArgumentException("Could not load keystore");
        }
        try(InputStream is = stream) {
            KeyStore loadedKeystore = KeyStore.getInstance("JKS");
            loadedKeystore.load(is, storePw.toCharArray());
            return loadedKeystore;
        }
    }
	
    private static void msg()
    {
    	System.out.println("\nJava NIO Reverse Proxy with AWSv4 Signing and SSL \n");
		  System.out.println("Copyright 2018. Designed & Developed in India.\n");
		  System.out.println("Takes 1 argument pointing to a properties file\n");
		  System.out.println("The following are the properties \n"
		  		+ "keyStorePath : Location to the SSL keystore of the proxy server \n"
		  		+ "keyStorePass : Password for the SSL keystore \n"
		  		+ "trustStorePath : Location to the SSL trusttore of the proxy client \n"
		  		+ "trustStorePass : Password for the SSL truststore \n"
		  		+ "awsCredProvider : AWS credentials provider. Set it to 'auto' for default credentials provider or set it to a location of a AWS credentials properties file \n"
		  		+ "awsService : The AWS service for which we are reverse proxying \n"
		  		+ "awsRegion : The AWS region of the above AWS service \n"
		  		+ "maxBuffers : The maximum number of request buffers that the proxy server can accept from clients \n"
		  		+ "totalBackends : The total number of backend servers we are configuring \n"
		  		+ "proxy.prefix.1 : The path prefix in the proxy server under which the 1st backend server will be available \n"
		  		+ "proxy.hosts.1 : The hosts of the 1st backend servers we are proxying \n"
		  		+ "proxy.prefix.<n> : The path prefix in the proxy server under which the nth backend server will be available \n"
		  		+ "proxy.hosts.<n> : The hosts of the nth backend servers we are proxying \n"
		  		+ "proxy.hosts.<n> : The hosts of the nth backend servers we are proxying \n"
		  		+ "bindAddress : The bind address of the proxy server \n"
		  		+ "httpPort : The HTTP port under which the proxy server will be available \n"
		  		+ "httpsPort : The HTTPs port under which the proxy server will be available \n"
		  		+ "maxRequestTime : The maximum time for a request to be processed before timing out \n"
		  		+ "connectionsPerThread : The number of connections per thread that can be handeled by the proxy client \n"
		  		+ "ioThreads : The number of NIO non-blocking threads for listeners, selection, async read and write etc. \n"
		  		+ "workerThreads : The number of blocking threads for workers \n"
		  		+ "workerTaskMaxThreads : The maximum number of blocking worker threads that is permissible \n"		  		
		  		+ "auth.s3Region : The AWS S3 region where the basic auth file is available \n"
		  		+ "auth.s3JsonFile : The basic auth json file available in AWS S3 \n"
		  		+ "log.groupName : The AWS CloudWatch group name \n"		  		
		  		+ "log.streamName : The AWS CloudWatch stream name \n"
		  		+ "log.region : The AWS CloudWatch region \n"
		  		+ "\n"
		  		+ "Powered by Undertow 2.0 \n"
		  		+ "");
		  System.exit(1);
    }
	
}

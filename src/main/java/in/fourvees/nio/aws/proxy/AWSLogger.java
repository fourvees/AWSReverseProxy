package in.fourvees.nio.aws.proxy;


import java.util.ArrayList;
import java.util.Calendar;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchAsync;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchAsyncClientBuilder;
import com.amazonaws.services.cloudwatch.model.Dimension;
import com.amazonaws.services.cloudwatch.model.MetricDatum;
import com.amazonaws.services.cloudwatch.model.PutMetricDataRequest;
import com.amazonaws.services.cloudwatch.model.StandardUnit;
import com.amazonaws.services.logs.AWSLogsAsync;
import com.amazonaws.services.logs.AWSLogsAsyncClientBuilder;
import com.amazonaws.services.logs.model.CreateLogStreamRequest;
import com.amazonaws.services.logs.model.InputLogEvent;
import com.amazonaws.services.logs.model.PutLogEventsRequest;
import com.amazonaws.services.logs.model.PutLogEventsResult;

public class AWSLogger {

	private  AWSLogsAsync logclient;	
	private  String logStreamName = "dev-";
	private  Future<PutLogEventsResult> future=null;
	
	private static  String logGroupName = "";
	private static AWSLogger instance;
	
	private AWSLogger()
	{}
	
	public static AWSLogger getInstance(Properties conf,AWSCredentialsProvider cre) 
	{
		synchronized(AWSLogger.class)
	      {
		    if (instance == null) 
		    {		     		    	
		      instance = new AWSLogger();
		      instance.setUp(conf,cre);		      
		      instance.log("AWS CloudWatch Logger v1.0");
		      instance.log("Designed & Developed in India");
		    }
	      }
	    return instance;
	  }
	
	private void setUp(Properties conf,AWSCredentialsProvider cre)
	{
		try{
		logGroupName = conf.getProperty("log.groupName"); 		
		logclient = AWSLogsAsyncClientBuilder.standard().withCredentials(cre).withRegion(conf.getProperty("log.region")).build();		
		if(null==conf)
			conf = new Properties();
		logStreamName = conf.getProperty("log.streamName", logStreamName) + String.valueOf(Calendar.getInstance().getTimeInMillis());
		logclient.createLogStream(new CreateLogStreamRequest(conf.getProperty("log.groupName", logGroupName), logStreamName));		
		}catch(Exception e) {}
	}
		
	public synchronized void log(String msg)
	{		
		try{
			if(null!=msg && msg.length()>0)
			{
				PutLogEventsRequest  req = new PutLogEventsRequest();
				ArrayList<InputLogEvent> logs = new ArrayList<>();
				InputLogEvent evt = new InputLogEvent();		
				evt.setMessage(msg);		
				evt.setTimestamp(Calendar.getInstance().getTimeInMillis());		
				logs.add(evt);		
				req.setLogGroupName(logGroupName);
				req.setLogStreamName(logStreamName);
				req.setLogEvents(logs);
				if(null!=future)
					req.setSequenceToken(future.get().getNextSequenceToken());
				//synchronized (AWSLogger.class) {
					future = logclient.putLogEventsAsync(req);
				//}
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		
	}
}

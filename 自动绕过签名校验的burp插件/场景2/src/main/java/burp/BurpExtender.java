package burp;


import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender,IHttpListener {
    private PrintWriter stdout;
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks){
        stdout = new PrintWriter(callbacks.getStdout(), true);
        helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        //设置burp插件名称
        callbacks.setExtensionName("更新api_sign");
        callbacks.registerHttpListener(this);
    }



    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        String data = "";
        String sig = "";
        String timestamp = String.valueOf(System.currentTimeMillis()/1000);
        byte [] req = messageInfo.getRequest();

        if(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER && messageIsRequest){
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);

            List<IParameter> parameters = requestInfo.getParameters();

            for(IParameter parameter : parameters){
                if(parameter.getType() == IParameter.PARAM_URL){
                    //移除原来的api_sign
                    if("sig".equals(parameter.getName())){

                        req = helpers.removeParameter(req, parameter);

                    }

                    else if ("timestamp".equals(parameter.getName())) {
                        data += parameter.getName()+"="+timestamp+"&";
                        req = helpers.updateParameter(req, helpers.buildParameter("timestamp",timestamp,IParameter.PARAM_URL));
                    }

                    else {
                        data += parameter.getName()+"="+parameter.getValue()+"&";
                    }
                }
            }

            String Authorization = requestInfo.getHeaders().get(4).split(": ")[1];


            //生成新签名
            String apiKey = "apiKey=wxe0464377ab4efc7c";


            String str3 = "";

            stdout.println(data);
            String[] arg = data.split("&");
            Arrays.sort(arg);
            for(String a:arg){

                str3+=a+"&";
            }
            str3 = str3.substring(0,str3.length()-1);

            String finalStr = apiKey+"&"+str3+Authorization;
            stdout.println(finalStr);

            sig = MD5Util.getMD5Str(finalStr);
            stdout.println("sig: "+sig);
            messageInfo.setRequest(helpers.addParameter(req,helpers.buildParameter("sig",sig,IParameter.PARAM_URL)));
        }

    }


}
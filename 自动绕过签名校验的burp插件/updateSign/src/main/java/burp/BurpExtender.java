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
        String api_sign = "";
        byte [] req = messageInfo.getRequest();
        if(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER && messageIsRequest){
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            List<IParameter> parameters = requestInfo.getParameters();

            for(IParameter parameter : parameters){
                if(parameter.getType() == IParameter.PARAM_URL){
                    //移除原来的api_sign
                    if("api_sign".equals(parameter.getName())){
                        req = helpers.removeParameter(req, parameter);
                    }
                    else {
                        data += parameter.getName()+"="+parameter.getValue()+"&";
                    }
                }
            }

            //生成新签名
            String apppwd = "72e78efefe6b4577a1f7afbca56b6e28993c06ea4bb84cde8dd70e582dbc76cb";
            String appkey = "f6aefd6691f04573bdf9e044137372bc";

            String str3 = "";
            String[] arg = data.split("&");
            Arrays.sort(arg);
            for(String a:arg){

                str3+=a+"&";
            }
            str3 = str3.substring(0,str3.length()-1);
            stdout.println(str3);
            String finalStr = appkey+"Oic"+apppwd+"QeeeS99u3d"+str3+appkey+apppwd;

            api_sign = MD5Util.getMD5Str(finalStr);
            stdout.println("api_sign: "+api_sign);
            messageInfo.setRequest(helpers.addParameter(req,
                    helpers.buildParameter("api_sign",api_sign,IParameter.PARAM_URL)));
        }

    }


}
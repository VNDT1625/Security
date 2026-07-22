const DEFAULT_BASE="http://localhost:8000";const DEFAULT_TIMEOUT=4500;const URL_ASSESS_TIMEOUT=60000;
export async function getBaseUrl(){try{const {apiBaseUrl}=await chrome.storage.local.get("apiBaseUrl");return (apiBaseUrl||DEFAULT_BASE).replace(/\/$/,"")}catch{return DEFAULT_BASE}}
async function authHeaders(json=true){const {extensionApiKey}=await chrome.storage.local.get("extensionApiKey");const headers={"X-Client-Id":"extension"};if(json)headers["Content-Type"]="application/json";if(extensionApiKey)headers.Authorization=`Bearer ${extensionApiKey}`;return headers}
export class ApiError extends Error{constructor(type,message,status=null,retryAfter=0){super(message);this.name="ApiError";this.type=type;this.status=status;this.retryAfter=retryAfter}}
async function request(path,options={},timeoutMs=DEFAULT_TIMEOUT){const base=await getBaseUrl();const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeoutMs);try{const res=await fetch(`${base}${path}`,{...options,headers:{...(await authHeaders(options.body instanceof FormData?false:true)),...options.headers},signal:controller.signal});if(!res.ok){const retryAfter=Number(res.headers.get("Retry-After"))||0;let detail="";try{const data=await res.json();detail=data.detail||data.error||""}catch{}throw new ApiError("http",detail||`Gateway trả về lỗi ${res.status}.`,res.status,retryAfter)}try{return await res.json()}catch{throw new ApiError("invalid_response","Gateway trả về dữ liệu không hợp lệ.")}}catch(error){if(error instanceof ApiError)throw error;if(error?.name==="AbortError")throw new ApiError("timeout",`Gateway không phản hồi sau ${Math.round(timeoutMs/1000)} giây.`);throw new ApiError("network","Không thể kết nối tới Gateway.")}finally{clearTimeout(timer)}}
const post=(path,body,timeoutMs)=>request(path,{method:"POST",body:JSON.stringify(body)},timeoutMs);
export const verifyExtensionKey=()=>request("/v1/auth/extension/verify",{method:"GET"});
export async function assessUrl(url,context=""){
  const result=await post("/v1/demo/url/analyze",{
    url,
    deep_analysis:true,
    advanced_analysis:false,
    llm_context:context||undefined,
    ai_context:"off",
  },URL_ASSESS_TIMEOUT);
  const responseScore=Number(result.risk_score||0);
  const coreFinalScore=Number(result.risk_core?.final_score);
  const normalizedScore=Number.isFinite(coreFinalScore)
    ?coreFinalScore/100
    :result.score_scale==="0..100"||responseScore>1?responseScore/100:responseScore;
  const evidence=Array.isArray(result.evidence)?result.evidence:[];
  return {
    ...result,
    risk_score:Math.max(0,Math.min(1,normalizedScore)),
    source_risk_score:responseScore,
    latency_ms:result.analysis_time_ms??result.latency_ms,
    reasons:Array.isArray(result.reasons)&&result.reasons.length
      ?result.reasons
      :evidence.filter((item)=>item?.triggered!==false).map((item)=>item?.message||item?.reason).filter(Boolean),
  };
}
export const assessText=(text,modality="email",metadata=null)=>post("/v1/assess/text",{text,modality,metadata},6500);
export const assessAction=(actionType,targetUrl,dataTypes=[])=>post("/v1/assess/action",{action_type:actionType,target_url:targetUrl,data_types:dataTypes,agent_context:{agent_type:"browser_agent"}});
export function assessExecutable(filename,bytes,mimeType="application/octet-stream"){
  const form=new FormData();
  form.append("file",new Blob([bytes],{type:mimeType}),filename);
  form.append("share_with_provider","false");
  return request("/v1/assess/file/exe-quick-scan",{method:"POST",body:form},20000);
}
